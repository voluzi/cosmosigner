package signer

import (
	"crypto/sha256"
	"testing"
	"time"

	"github.com/cometbft/cometbft/crypto/ed25519"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cometbft/cometbft/types"
	"github.com/stretchr/testify/require"

	"github.com/voluzi/cosmosigner/internal/backend"
	"github.com/voluzi/cosmosigner/internal/state"
)

const testChain = "signer-test-chain"

// memStore is a minimal in-memory StateStore for signer unit tests.
type memStore struct {
	st map[string]*state.SignState
}

func newMemStore() *memStore { return &memStore{st: map[string]*state.SignState{}} }

func (m *memStore) Reserve(chainID string, h int64, r int32, s int8, sb []byte, ts time.Time) (state.ReserveResult, error) {
	cur := m.st[chainID]
	if cur != nil {
		if h < cur.Height || (h == cur.Height && r < cur.Round) || (h == cur.Height && r == cur.Round && s < cur.Step) {
			return state.ReserveResult{}, state.ErrRegression
		}
		if h == cur.Height && r == cur.Round && s == cur.Step {
			if string(cur.SignBytes) == string(sb) {
				return state.ReserveResult{Reuse: true, SignBytes: cur.SignBytes, Signature: cur.Signature, Timestamp: cur.Timestamp}, nil
			}
			return state.ReserveResult{}, state.ErrConflict
		}
	}
	m.st[chainID] = &state.SignState{Height: h, Round: r, Step: s, SignBytes: sb, Timestamp: ts}
	return state.ReserveResult{SignBytes: sb, Timestamp: ts}, nil
}

func (m *memStore) Commit(chainID string, h int64, r int32, s int8, sb, sig []byte) error {
	m.st[chainID].Signature = sig
	return nil
}

func (m *memStore) Get(chainID string) (*state.SignState, error) {
	st, ok := m.st[chainID]
	if !ok {
		return nil, state.ErrNoState
	}
	return st, nil
}
func (m *memStore) IsLeader() bool        { return true }
func (m *memStore) LeaderCh() <-chan bool { return nil }
func (m *memStore) Close() error          { return nil }

func newTestPV(t *testing.T) *GatedPrivValidator {
	t.Helper()
	pv, err := New(backend.NewSoftwareFromPriv(ed25519.GenPrivKey()), newMemStore())
	require.NoError(t, err)
	return pv
}

func hash32(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

func TestSignVote_NilVote(t *testing.T) {
	pv := newTestPV(t)
	require.ErrorContains(t, pv.SignVote(testChain, nil), "nil vote")
}

func TestSignProposal_NilProposal(t *testing.T) {
	pv := newTestPV(t)
	require.ErrorContains(t, pv.SignProposal(testChain, nil), "nil proposal")
}

func TestSignVote_MalformedBlockIDDoesNotPanic(t *testing.T) {
	pv := newTestPV(t)
	vote := &cmtproto.Vote{
		Type:   cmtproto.PrecommitType,
		Height: 5,
		BlockID: cmtproto.BlockID{
			Hash: []byte("short"), // invalid size — cometbft canonicalization panics on this
			PartSetHeader: cmtproto.PartSetHeader{
				Total: 1,
				Hash:  []byte("also-short"),
			},
		},
		Timestamp: time.Now().UTC(),
	}
	err := pv.SignVote(testChain, vote)
	require.ErrorContains(t, err, "invalid sign request")
}

func TestSignVote_UnknownVoteType(t *testing.T) {
	pv := newTestPV(t)
	vote := &cmtproto.Vote{Type: 42, Height: 5, Timestamp: time.Now().UTC()}
	require.ErrorContains(t, pv.SignVote(testChain, vote), "unknown vote type")
}

func TestSignVote_HappyPathVerifies(t *testing.T) {
	pv := newTestPV(t)
	vote := &cmtproto.Vote{
		Type:   cmtproto.PrecommitType,
		Height: 7,
		BlockID: cmtproto.BlockID{
			Hash:          hash32("block"),
			PartSetHeader: cmtproto.PartSetHeader{Total: 1, Hash: hash32("parts")},
		},
		Timestamp: time.Now().UTC(),
	}
	require.NoError(t, pv.SignVote(testChain, vote))
	pub, err := pv.GetPubKey()
	require.NoError(t, err)
	require.True(t, pub.VerifySignature(types.VoteSignBytes(testChain, vote), vote.Signature))
}
