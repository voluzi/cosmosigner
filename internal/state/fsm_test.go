package state

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"io"
	"testing"
	"time"

	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cometbft/cometbft/types"
	"github.com/hashicorp/raft"
	"github.com/stretchr/testify/require"
)

const testChain = "test-chain-1"

var (
	ts1 = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	ts2 = ts1.Add(2 * time.Second)
)

func hash32(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

func voteSignBytes(height int64, round int32, ts time.Time, blockHash string) []byte {
	v := &cmtproto.Vote{
		Type:   cmtproto.PrecommitType,
		Height: height,
		Round:  round,
		BlockID: cmtproto.BlockID{
			Hash:          hash32(blockHash),
			PartSetHeader: cmtproto.PartSetHeader{Total: 1, Hash: hash32(blockHash + "-parts")},
		},
		Timestamp: ts,
	}
	return types.VoteSignBytes(testChain, v)
}

func reserve(f *fsm, h int64, r int32, s int8, sb []byte, ts time.Time) applyResult {
	data, _ := json.Marshal(command{Op: opReserve, ChainID: testChain, Height: h, Round: r, Step: s, SignBytes: sb, Timestamp: ts})
	return f.Apply(&raft.Log{Data: data}).(applyResult)
}

func commit(f *fsm, h int64, r int32, s int8, sb, sig []byte) applyResult {
	data, _ := json.Marshal(command{Op: opCommit, ChainID: testChain, Height: h, Round: r, Step: s, SignBytes: sb, Signature: sig})
	return f.Apply(&raft.Log{Data: data}).(applyResult)
}

type snapshotSink struct {
	bytes.Buffer
	closed   bool
	canceled bool
}

func (s *snapshotSink) ID() string { return "test-snapshot" }

func (s *snapshotSink) Close() error {
	s.closed = true
	return nil
}

func (s *snapshotSink) Cancel() error {
	s.canceled = true
	return nil
}

func TestFSM_FreshAdvanceProceeds(t *testing.T) {
	f := newFSM()
	sb := voteSignBytes(100, 0, ts1, "block-A")
	res := reserve(f, 100, 0, StepPrecommit, sb, ts1)
	require.NoError(t, res.err)
	require.False(t, res.reuse)
	require.Equal(t, sb, res.signBytes)
}

func TestFSM_HeightRegression(t *testing.T) {
	f := newFSM()
	require.NoError(t, reserve(f, 100, 0, StepPrecommit, voteSignBytes(100, 0, ts1, "A"), ts1).err)
	res := reserve(f, 99, 0, StepPrecommit, voteSignBytes(99, 0, ts1, "B"), ts1)
	require.ErrorIs(t, res.err, ErrRegression)
}

func TestFSM_StepRegression(t *testing.T) {
	f := newFSM()
	require.NoError(t, reserve(f, 100, 0, StepPrecommit, voteSignBytes(100, 0, ts1, "A"), ts1).err)
	// prevote (step 2) after precommit (step 3) at same height/round is a regression
	res := reserve(f, 100, 0, StepPrevote, voteSignBytes(100, 0, ts1, "A"), ts1)
	require.ErrorIs(t, res.err, ErrRegression)
}

func TestFSM_StepAdvanceWithinHeight(t *testing.T) {
	f := newFSM()
	require.NoError(t, reserve(f, 100, 0, StepPropose, voteSignBytes(100, 0, ts1, "A"), ts1).err)
	require.NoError(t, reserve(f, 100, 0, StepPrevote, voteSignBytes(100, 0, ts1, "A"), ts1).err)
	require.NoError(t, reserve(f, 100, 0, StepPrecommit, voteSignBytes(100, 0, ts1, "A"), ts1).err)
}

func TestFSM_IdenticalReuseAfterCommit(t *testing.T) {
	f := newFSM()
	sb := voteSignBytes(100, 0, ts1, "A")
	require.NoError(t, reserve(f, 100, 0, StepPrecommit, sb, ts1).err)
	sig := []byte("signature-bytes-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	require.NoError(t, commit(f, 100, 0, StepPrecommit, sb, sig).err)

	res := reserve(f, 100, 0, StepPrecommit, sb, ts1)
	require.NoError(t, res.err)
	require.True(t, res.reuse)
	require.Equal(t, sig, res.signature)
}

func TestFSM_TimestampOnlyDiffReuses(t *testing.T) {
	f := newFSM()
	sb1 := voteSignBytes(100, 0, ts1, "A")
	require.NoError(t, reserve(f, 100, 0, StepPrecommit, sb1, ts1).err)
	sig := []byte("signature-bytes-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	require.NoError(t, commit(f, 100, 0, StepPrecommit, sb1, sig).err)

	// Same vote, different timestamp only.
	sb2 := voteSignBytes(100, 0, ts2, "A")
	require.NotEqual(t, sb1, sb2)
	res := reserve(f, 100, 0, StepPrecommit, sb2, ts2)
	require.NoError(t, res.err)
	require.True(t, res.reuse)
	require.Equal(t, sig, res.signature)
	require.True(t, res.timestamp.Equal(ts1), "should return the originally-signed timestamp")
}

func TestFSM_ConflictOnDifferentBlock(t *testing.T) {
	f := newFSM()
	sb1 := voteSignBytes(100, 0, ts1, "A")
	require.NoError(t, reserve(f, 100, 0, StepPrecommit, sb1, ts1).err)
	require.NoError(t, commit(f, 100, 0, StepPrecommit, sb1, []byte("sig")).err)

	sb2 := voteSignBytes(100, 0, ts1, "DIFFERENT-BLOCK")
	res := reserve(f, 100, 0, StepPrecommit, sb2, ts1)
	require.ErrorIs(t, res.err, ErrConflict)
}

func TestFSM_InFlightIdenticalProceeds(t *testing.T) {
	f := newFSM()
	sb := voteSignBytes(100, 0, ts1, "A")
	require.NoError(t, reserve(f, 100, 0, StepPrecommit, sb, ts1).err) // reserved, not committed

	// Concurrent request for the same bytes before commit: proceed (re-sign same bytes).
	res := reserve(f, 100, 0, StepPrecommit, sb, ts1)
	require.NoError(t, res.err)
	require.False(t, res.reuse)
	require.Equal(t, sb, res.signBytes)
}

func TestFSM_CommitMismatchRejected(t *testing.T) {
	f := newFSM()
	sb := voteSignBytes(100, 0, ts1, "A")
	require.NoError(t, reserve(f, 100, 0, StepPrecommit, sb, ts1).err)
	// commit for different bytes than reserved
	res := commit(f, 100, 0, StepPrecommit, voteSignBytes(100, 0, ts1, "OTHER"), []byte("sig"))
	require.Error(t, res.err)
}

func TestFSM_RestoreRejectsInvalidSnapshotWithoutChangingState(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{name: "empty", data: nil},
		{name: "null", data: []byte("null")},
		{name: "truncated", data: []byte(`{"test-chain-1":`)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFSM()
			sb := voteSignBytes(100, 2, ts1, "A")
			sig := []byte("signature")
			require.NoError(t, reserve(f, 100, 2, StepPrecommit, sb, ts1).err)
			require.NoError(t, commit(f, 100, 2, StepPrecommit, sb, sig).err)
			want := f.get(testChain)

			err := f.Restore(io.NopCloser(bytes.NewReader(tt.data)))

			require.Error(t, err)
			require.Equal(t, want, f.get(testChain))
		})
	}
}

func TestFSM_RestoreAcceptsEmptyObject(t *testing.T) {
	f := newFSM()
	require.NoError(t, reserve(f, 100, 0, StepPrecommit, voteSignBytes(100, 0, ts1, "A"), ts1).err)

	require.NoError(t, f.Restore(io.NopCloser(bytes.NewReader([]byte("{}")))))

	require.NotNil(t, f.state)
	require.Empty(t, f.state)
}

func TestFSM_SnapshotPersistRestoreRoundTrip(t *testing.T) {
	f := newFSM()
	sb := voteSignBytes(100, 2, ts1, "A")
	sig := []byte("signature")
	require.NoError(t, reserve(f, 100, 2, StepPrecommit, sb, ts1).err)
	require.NoError(t, commit(f, 100, 2, StepPrecommit, sb, sig).err)
	want := f.get(testChain)

	snapshot, err := f.Snapshot()
	require.NoError(t, err)
	sink := &snapshotSink{}
	require.NoError(t, snapshot.Persist(sink))
	require.True(t, sink.closed)
	require.False(t, sink.canceled)

	restored := newFSM()
	require.NoError(t, restored.Restore(io.NopCloser(bytes.NewReader(sink.Bytes()))))
	require.Equal(t, want, restored.get(testChain))

	res := reserve(restored, 99, 0, StepPrecommit, voteSignBytes(99, 0, ts1, "B"), ts1)
	require.ErrorIs(t, res.err, ErrRegression)
}
