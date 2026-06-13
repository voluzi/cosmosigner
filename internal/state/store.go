// Package state provides the linearizable high-water-mark gate that prevents
// double-signing. The single v1 implementation is backed by embedded
// hashicorp/raft: every signature must pass through a raft-committed
// "reserve" of its (height, round, step), so a minority-partitioned signer
// cannot advance the mark and therefore cannot sign — it fails closed.
package state

import (
	"errors"
	"time"
)

// CometBFT consensus step values (mirrors cometbft/privval step constants).
const (
	StepNone      int8 = 0
	StepPropose   int8 = 1
	StepPrevote   int8 = 2
	StepPrecommit int8 = 3
)

// SignState is the last signature decision for a chain — the high-water-mark.
type SignState struct {
	Height    int64     `json:"height"`
	Round     int32     `json:"round"`
	Step      int8      `json:"step"`
	SignBytes []byte    `json:"sign_bytes,omitempty"`
	Signature []byte    `json:"signature,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// ReserveResult tells the caller how to proceed after a reservation.
//
//   - Reuse == true: a signature already exists for this height/round/step
//     (identical bytes, or differing only by timestamp). The caller MUST NOT
//     sign again — it stamps Timestamp and Signature onto the vote/proposal.
//   - Reuse == false: the caller must Sign(SignBytes), then Commit, and stamp
//     Timestamp. SignBytes equals the caller's own bytes for a fresh height; for
//     an in-flight reservation it is the already-reserved bytes, so the cluster
//     only ever signs one set of bytes per height/round/step.
type ReserveResult struct {
	Reuse     bool
	SignBytes []byte
	Signature []byte
	Timestamp time.Time
}

// StateStore is the linearizable double-sign gate.
type StateStore interface {
	// Reserve atomically checks (height,round,step) against the high-water-mark
	// and advances it when valid. Returns ErrRegression / ErrConflict when the
	// request would double-sign, and ErrNotLeader when this node can't gate.
	Reserve(chainID string, height int64, round int32, step int8, signBytes []byte, ts time.Time) (ReserveResult, error)
	// Commit records the produced signature so idempotent re-requests can reuse
	// it without re-signing.
	Commit(chainID string, height int64, round int32, step int8, signBytes, signature []byte) error
	// Get returns the current high-water-mark for a chain.
	Get(chainID string) (*SignState, error)
	// IsLeader reports whether this node currently holds raft leadership.
	IsLeader() bool
	// LeaderCh signals leadership acquisition (true) and loss (false).
	LeaderCh() <-chan bool
	Close() error
}

var (
	// ErrRegression means the request's height/round/step is below the mark.
	ErrRegression = errors.New("hrs regression")
	// ErrConflict means a different payload was requested at an already-signed
	// height/round/step — a double-sign attempt.
	ErrConflict = errors.New("conflicting sign request for same height/round/step")
	// ErrNotLeader means this node is not the raft leader and cannot gate.
	ErrNotLeader = errors.New("not raft leader")
	// ErrNoState means no high-water-mark exists yet for the chain.
	ErrNoState = errors.New("no state for chain")
)
