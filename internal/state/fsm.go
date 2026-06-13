package state

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/cometbft/cometbft/libs/protoio"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	gogoproto "github.com/cosmos/gogoproto/proto"
	"github.com/hashicorp/raft"
)

type opType string

const (
	opReserve opType = "reserve"
	opCommit  opType = "commit"
)

type command struct {
	Op        opType    `json:"op"`
	ChainID   string    `json:"chain_id"`
	Height    int64     `json:"height"`
	Round     int32     `json:"round"`
	Step      int8      `json:"step"`
	SignBytes []byte    `json:"sign_bytes,omitempty"`
	Signature []byte    `json:"signature,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// applyResult is returned from FSM.Apply via raft's ApplyFuture.Response().
// Business errors ride in err because FSM.Apply cannot return an error directly.
type applyResult struct {
	reuse     bool
	signBytes []byte
	signature []byte
	timestamp time.Time
	err       error
}

// fsm is the replicated state machine holding the per-chain high-water-mark.
type fsm struct {
	mu    sync.RWMutex
	state map[string]*SignState
}

func newFSM() *fsm {
	return &fsm{state: make(map[string]*SignState)}
}

func (f *fsm) Apply(l *raft.Log) any {
	var c command
	if err := json.Unmarshal(l.Data, &c); err != nil {
		return applyResult{err: fmt.Errorf("unmarshal command: %w", err)}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	switch c.Op {
	case opReserve:
		return f.applyReserve(c)
	case opCommit:
		return f.applyCommit(c)
	default:
		return applyResult{err: fmt.Errorf("unknown op %q", c.Op)}
	}
}

// applyReserve enforces the double-sign invariant, mirroring cometbft FilePV:
// at a given height/round/step the cluster signs exactly one set of bytes; a
// re-request that differs only by timestamp reuses that signature.
func (f *fsm) applyReserve(c command) applyResult {
	cur := f.state[c.ChainID]
	switch compareHRS(cur, c.Height, c.Round, c.Step) {
	case -1:
		return applyResult{err: ErrRegression}
	case 0:
		if bytes.Equal(cur.SignBytes, c.SignBytes) {
			if len(cur.Signature) > 0 {
				return applyResult{reuse: true, signature: cur.Signature, timestamp: cur.Timestamp}
			}
			// In-flight reservation, same bytes: caller re-signs the identical
			// bytes (ed25519 deterministic) and commits idempotently.
			return applyResult{signBytes: cur.SignBytes, timestamp: cur.Timestamp}
		}
		if ts, ok := onlyDiffersByTimestamp(cur.SignBytes, c.SignBytes, c.Step); ok {
			if len(cur.Signature) > 0 {
				return applyResult{reuse: true, signature: cur.Signature, timestamp: ts}
			}
			// In-flight reservation, timestamp-only diff: caller signs the
			// reserved bytes and stamps the reserved timestamp.
			return applyResult{signBytes: cur.SignBytes, timestamp: ts}
		}
		return applyResult{err: ErrConflict}
	default: // +1: advance the high-water-mark
		f.state[c.ChainID] = &SignState{
			Height:    c.Height,
			Round:     c.Round,
			Step:      c.Step,
			SignBytes: c.SignBytes,
			Timestamp: c.Timestamp,
		}
		return applyResult{signBytes: c.SignBytes, timestamp: c.Timestamp}
	}
}

func (f *fsm) applyCommit(c command) applyResult {
	cur := f.state[c.ChainID]
	if cur == nil || cur.Height != c.Height || cur.Round != c.Round || cur.Step != c.Step {
		return applyResult{err: fmt.Errorf("commit for stale or unknown height/round/step")}
	}
	if !bytes.Equal(cur.SignBytes, c.SignBytes) {
		return applyResult{err: fmt.Errorf("commit sign-bytes mismatch")}
	}
	if len(cur.Signature) > 0 {
		if !bytes.Equal(cur.Signature, c.Signature) {
			return applyResult{err: fmt.Errorf("commit signature mismatch for same bytes")}
		}
		return applyResult{}
	}
	cur.Signature = c.Signature
	return applyResult{}
}

func (f *fsm) get(chainID string) *SignState {
	f.mu.RLock()
	defer f.mu.RUnlock()
	st, ok := f.state[chainID]
	if !ok {
		return nil
	}
	cp := *st
	cp.SignBytes = append([]byte(nil), st.SignBytes...)
	cp.Signature = append([]byte(nil), st.Signature...)
	return &cp
}

// compareHRS returns -1 if (h,r,s) regresses below cur, 0 if equal, +1 if it
// advances. A nil cur (no prior state) always advances. Direct comparisons —
// no subtraction — so extreme values cannot overflow.
func compareHRS(cur *SignState, h int64, r int32, s int8) int {
	if cur == nil {
		return 1
	}
	switch {
	case h < cur.Height:
		return -1
	case h > cur.Height:
		return 1
	}
	switch {
	case r < cur.Round:
		return -1
	case r > cur.Round:
		return 1
	}
	switch {
	case s < cur.Step:
		return -1
	case s > cur.Step:
		return 1
	}
	return 0
}

// onlyDiffersByTimestamp reports whether two sign-byte payloads are identical
// except for their timestamp, returning the previous timestamp. Mirrors
// cometbft FilePV.checkVotesOnlyDifferByTimestamp / checkProposals... but uses a
// fixed zero time (instead of time.Now) so the comparison is deterministic
// across raft replicas. Unmarshal failures are treated as "not equal" (conflict).
func onlyDiffersByTimestamp(lastSignBytes, newSignBytes []byte, step int8) (time.Time, bool) {
	if step == StepPropose {
		var last, next cmtproto.CanonicalProposal
		if protoio.UnmarshalDelimited(lastSignBytes, &last) != nil || protoio.UnmarshalDelimited(newSignBytes, &next) != nil {
			return time.Time{}, false
		}
		lastTime := last.Timestamp
		var fixed time.Time
		last.Timestamp, next.Timestamp = fixed, fixed
		return lastTime, gogoproto.Equal(&last, &next)
	}
	var last, next cmtproto.CanonicalVote
	if protoio.UnmarshalDelimited(lastSignBytes, &last) != nil || protoio.UnmarshalDelimited(newSignBytes, &next) != nil {
		return time.Time{}, false
	}
	lastTime := last.Timestamp
	var fixed time.Time
	last.Timestamp, next.Timestamp = fixed, fixed
	return lastTime, gogoproto.Equal(&last, &next)
}
