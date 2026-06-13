// Package signer implements a cometbft types.PrivValidator that gates every
// signature behind the StateStore (the raft high-water-mark) before invoking the
// KeyBackend. The reserve→sign→commit ordering is the double-sign safety
// property: the mark advances (and is raft-committed) before any signature is
// produced.
package signer

import (
	"fmt"
	"time"

	"github.com/cometbft/cometbft/crypto"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cometbft/cometbft/types"

	"github.com/voluzi/cosmosigner/internal/backend"
	"github.com/voluzi/cosmosigner/internal/state"
)

// GatedPrivValidator is safe for concurrent use: it is shared across all
// per-node SignerServers, and the StateStore serializes reservations.
type GatedPrivValidator struct {
	backend backend.KeyBackend
	store   state.StateStore
	pub     crypto.PubKey
}

var _ types.PrivValidator = (*GatedPrivValidator)(nil)

// New builds a GatedPrivValidator, caching the public key up front.
func New(b backend.KeyBackend, s state.StateStore) (*GatedPrivValidator, error) {
	pub, err := b.PubKey()
	if err != nil {
		return nil, fmt.Errorf("get public key: %w", err)
	}
	return &GatedPrivValidator{backend: b, store: s, pub: pub}, nil
}

func (g *GatedPrivValidator) GetPubKey() (crypto.PubKey, error) { return g.pub, nil }

func (g *GatedPrivValidator) SignVote(chainID string, vote *cmtproto.Vote) (err error) {
	// Sign-bytes canonicalization panics on malformed input (e.g. a BlockID
	// hash of the wrong size). Requests arrive from remote nodes, and a panic
	// here would crash the signer — recover it into an error instead.
	defer recoverToError(&err)

	if vote == nil {
		return fmt.Errorf("nil vote")
	}
	step, err := voteToStep(vote)
	if err != nil {
		return err
	}
	signBytes := types.VoteSignBytes(chainID, vote)
	return g.gatedSign(chainID, vote.Height, vote.Round, step, signBytes, vote.Timestamp,
		func(sig []byte, ts time.Time) {
			vote.Timestamp = ts
			vote.Signature = sig
		})
}

func (g *GatedPrivValidator) SignProposal(chainID string, proposal *cmtproto.Proposal) (err error) {
	defer recoverToError(&err)

	if proposal == nil {
		return fmt.Errorf("nil proposal")
	}
	signBytes := types.ProposalSignBytes(chainID, proposal)
	return g.gatedSign(chainID, proposal.Height, proposal.Round, state.StepPropose, signBytes, proposal.Timestamp,
		func(sig []byte, ts time.Time) {
			proposal.Timestamp = ts
			proposal.Signature = sig
		})
}

// recoverToError converts a panic in the signing path into a returned error so
// a malformed request from one node cannot crash the signer.
func recoverToError(err *error) {
	if r := recover(); r != nil {
		*err = fmt.Errorf("invalid sign request: %v", r)
	}
}

// gatedSign runs the reserve→sign→commit sequence and applies the result via set.
func (g *GatedPrivValidator) gatedSign(chainID string, height int64, round int32, step int8, signBytes []byte, ts time.Time, set func(sig []byte, ts time.Time)) error {
	res, err := g.store.Reserve(chainID, height, round, step, signBytes, ts)
	if err != nil {
		return err // ErrRegression / ErrConflict / ErrNotLeader → refuse to sign
	}
	if res.Reuse && len(res.Signature) > 0 {
		set(res.Signature, res.Timestamp)
		return nil
	}
	// Sign exactly the bytes the cluster reserved (res.SignBytes), then persist.
	sig, err := g.backend.Sign(res.SignBytes)
	if err != nil {
		return fmt.Errorf("backend sign: %w", err)
	}
	if err := g.store.Commit(chainID, height, round, step, res.SignBytes, sig); err != nil {
		return fmt.Errorf("commit signature: %w", err)
	}
	set(sig, res.Timestamp)
	return nil
}

func voteToStep(vote *cmtproto.Vote) (int8, error) {
	switch vote.Type {
	case cmtproto.PrevoteType:
		return state.StepPrevote, nil
	case cmtproto.PrecommitType:
		return state.StepPrecommit, nil
	default:
		return 0, fmt.Errorf("unknown vote type: %v", vote.Type)
	}
}
