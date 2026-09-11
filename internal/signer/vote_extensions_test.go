package signer

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/crypto/ed25519"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cometbft/cometbft/types"
	"github.com/stretchr/testify/require"

	"github.com/voluzi/cosmosigner/internal/backend"
	"github.com/voluzi/cosmosigner/internal/state"
)

type recordingBackend struct {
	key       backend.KeyBackend
	events    *[]string
	signCalls int
	failAt    map[int]error
}

func newRecordingBackend(events *[]string) *recordingBackend {
	return &recordingBackend{
		key:    backend.NewSoftwareFromPriv(ed25519.GenPrivKey()),
		events: events,
		failAt: make(map[int]error),
	}
}

func (b *recordingBackend) PubKey() (crypto.PubKey, error) { return b.key.PubKey() }

func (b *recordingBackend) Sign(signBytes []byte) ([]byte, error) {
	b.signCalls++
	if b.events != nil {
		*b.events = append(*b.events, fmt.Sprintf("backend-sign-%d", b.signCalls))
	}
	if err := b.failAt[b.signCalls]; err != nil {
		return nil, err
	}
	return b.key.Sign(signBytes)
}

func (b *recordingBackend) ClusterBinding(context.Context) (string, error) {
	return "", backend.ErrBindingUnsupported
}

func (b *recordingBackend) ClaimCluster(context.Context, string) error {
	return backend.ErrBindingUnsupported
}

func (b *recordingBackend) Close() error { return b.key.Close() }

type recordingStore struct {
	events        *[]string
	reserveResult state.ReserveResult
	reserveErr    error
	commitErr     error
	reserveCalls  int
	commitCalls   int
}

func (s *recordingStore) Reserve(_ string, _ int64, _ int32, _ int8, _ []byte, _ time.Time) (state.ReserveResult, error) {
	s.reserveCalls++
	if s.events != nil {
		*s.events = append(*s.events, "reserve")
	}
	return s.reserveResult, s.reserveErr
}

func (s *recordingStore) Commit(_ string, _ int64, _ int32, _ int8, _, _ []byte) error {
	s.commitCalls++
	if s.events != nil {
		*s.events = append(*s.events, "commit")
	}
	return s.commitErr
}

func (s *recordingStore) Get(string) (*state.SignState, error) { return nil, state.ErrNoState }

func (s *recordingStore) EnsureClusterID(context.Context) (string, error) {
	return "3b12f1df-5232-4804-897e-917bf397618a", nil
}

func (s *recordingStore) IsLeader() bool        { return true }
func (s *recordingStore) LeaderCh() <-chan bool { return nil }
func (s *recordingStore) Close() error          { return nil }

func extensionVote(extension []byte) *cmtproto.Vote {
	return &cmtproto.Vote{
		Type:   cmtproto.PrecommitType,
		Height: 7,
		Round:  2,
		BlockID: cmtproto.BlockID{
			Hash:          hash32("extension-block"),
			PartSetHeader: cmtproto.PartSetHeader{Total: 1, Hash: hash32("extension-parts")},
		},
		Timestamp: time.Date(2026, time.September, 11, 12, 0, 0, 0, time.UTC),
		Extension: extension,
	}
}

func newVoteExtensionPV(t *testing.T, b backend.KeyBackend, s state.StateStore) *GatedPrivValidator {
	t.Helper()
	pv, err := New(b, s)
	require.NoError(t, err)
	return pv
}

func TestSignVote_SignsVoteExtensions(t *testing.T) {
	tests := []struct {
		name      string
		extension []byte
	}{
		{name: "nonempty extension", extension: []byte("prices:v1")},
		{name: "empty extension", extension: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := newRecordingBackend(nil)
			pv := newVoteExtensionPV(t, b, newMemStore())
			vote := extensionVote(tt.extension)

			require.NoError(t, pv.SignVote(testChain, vote))
			pub, err := pv.GetPubKey()
			require.NoError(t, err)
			require.True(t, pub.VerifySignature(types.VoteSignBytes(testChain, vote), vote.Signature))
			require.True(t, pub.VerifySignature(types.VoteExtensionSignBytes(testChain, vote), vote.ExtensionSignature))
			require.Equal(t, 2, b.signCalls)
		})
	}
}

func TestSignVote_RejectsExtensionOutsideNonNilPrecommitBeforeSigning(t *testing.T) {
	tests := []struct {
		name string
		vote *cmtproto.Vote
	}{
		{
			name: "prevote",
			vote: &cmtproto.Vote{
				Type:      cmtproto.PrevoteType,
				Height:    7,
				Timestamp: time.Now().UTC(),
				Extension: []byte("not-allowed"),
			},
		},
		{
			name: "nil precommit",
			vote: &cmtproto.Vote{
				Type:      cmtproto.PrecommitType,
				Height:    7,
				Timestamp: time.Now().UTC(),
				Extension: []byte("not-allowed"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := newRecordingBackend(nil)
			s := &recordingStore{}
			pv := newVoteExtensionPV(t, b, s)
			before := *tt.vote

			err := pv.SignVote(testChain, tt.vote)

			require.ErrorContains(t, err, "vote extension")
			require.Equal(t, before, *tt.vote)
			require.Zero(t, s.reserveCalls)
			require.Zero(t, b.signCalls)
		})
	}
}

func TestSignVote_ClearsStaleExtensionSignatureWithoutSigningExtension(t *testing.T) {
	tests := []struct {
		name string
		vote *cmtproto.Vote
	}{
		{
			name: "prevote",
			vote: &cmtproto.Vote{
				Type:               cmtproto.PrevoteType,
				Height:             7,
				Timestamp:          time.Now().UTC(),
				ExtensionSignature: []byte("stale"),
			},
		},
		{
			name: "nil precommit",
			vote: &cmtproto.Vote{
				Type:               cmtproto.PrecommitType,
				Height:             7,
				Timestamp:          time.Now().UTC(),
				ExtensionSignature: []byte("stale"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := newRecordingBackend(nil)
			pv := newVoteExtensionPV(t, b, newMemStore())

			require.NoError(t, pv.SignVote(testChain, tt.vote))
			require.Empty(t, tt.vote.ExtensionSignature)
			require.Equal(t, 1, b.signCalls)
		})
	}
}

func TestSignVote_ReplayReusesCanonicalSignatureAndResignsChangedExtension(t *testing.T) {
	b := newRecordingBackend(nil)
	pv := newVoteExtensionPV(t, b, newMemStore())
	first := extensionVote([]byte("first"))
	require.NoError(t, pv.SignVote(testChain, first))
	firstSignature := append([]byte(nil), first.Signature...)
	firstExtensionSignature := append([]byte(nil), first.ExtensionSignature...)
	firstTimestamp := first.Timestamp

	replay := extensionVote([]byte("second"))
	replay.Timestamp = replay.Timestamp.Add(time.Minute)
	require.NoError(t, pv.SignVote(testChain, replay))

	pub, err := pv.GetPubKey()
	require.NoError(t, err)
	require.Equal(t, firstTimestamp, replay.Timestamp)
	require.Equal(t, firstSignature, replay.Signature)
	require.NotEqual(t, firstExtensionSignature, replay.ExtensionSignature)
	require.True(t, pub.VerifySignature(types.VoteExtensionSignBytes(testChain, replay), replay.ExtensionSignature))
	require.Equal(t, 3, b.signCalls, "the canonical signature is reused and each extension is signed")
}

func TestSignVote_FailureOrderLeavesVoteUnchanged(t *testing.T) {
	errReserve := errors.New("reserve failed")
	errCanonical := errors.New("canonical sign failed")
	errCommit := errors.New("commit failed")
	errExtension := errors.New("extension sign failed")
	tests := []struct {
		name      string
		reserve   error
		commit    error
		backendAt int
		backend   error
		wantErr   string
		wantOrder []string
	}{
		{name: "reserve", reserve: errReserve, wantErr: "reserve failed", wantOrder: []string{"reserve"}},
		{name: "canonical sign", backendAt: 1, backend: errCanonical, wantErr: "backend sign", wantOrder: []string{"reserve", "backend-sign-1"}},
		{name: "commit", commit: errCommit, wantErr: "commit signature", wantOrder: []string{"reserve", "backend-sign-1", "commit"}},
		{name: "extension sign", backendAt: 2, backend: errExtension, wantErr: "vote extension", wantOrder: []string{"reserve", "backend-sign-1", "commit", "backend-sign-2"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var events []string
			vote := extensionVote([]byte("payload"))
			before := *vote
			b := newRecordingBackend(&events)
			if tt.backendAt != 0 {
				b.failAt[tt.backendAt] = tt.backend
			}
			s := &recordingStore{
				events:        &events,
				reserveResult: state.ReserveResult{SignBytes: types.VoteSignBytes(testChain, vote), Timestamp: vote.Timestamp},
				reserveErr:    tt.reserve,
				commitErr:     tt.commit,
			}
			pv := newVoteExtensionPV(t, b, s)

			err := pv.SignVote(testChain, vote)

			require.ErrorContains(t, err, tt.wantErr)
			require.Equal(t, before, *vote)
			require.Equal(t, tt.wantOrder, events)
		})
	}
}

func TestSignVote_ExtensionFailureRetryReusesCommittedCanonicalSignature(t *testing.T) {
	b := newRecordingBackend(nil)
	b.failAt[2] = errors.New("extension unavailable")
	pv := newVoteExtensionPV(t, b, newMemStore())
	first := extensionVote([]byte("first"))
	before := *first

	err := pv.SignVote(testChain, first)
	require.ErrorContains(t, err, "vote extension")
	require.Equal(t, before, *first)

	retry := extensionVote([]byte("second"))
	retry.Timestamp = retry.Timestamp.Add(time.Minute)
	require.NoError(t, pv.SignVote(testChain, retry))
	require.Equal(t, before.Timestamp, retry.Timestamp)
	require.NotEmpty(t, retry.Signature)
	require.NotEmpty(t, retry.ExtensionSignature)
	require.Equal(t, 3, b.signCalls)
}
