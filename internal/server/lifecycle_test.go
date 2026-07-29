package server

import (
	"testing"
	"time"

	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/crypto/ed25519"
	privvalproto "github.com/cometbft/cometbft/proto/tendermint/privval"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cometbft/cometbft/types"
	"github.com/stretchr/testify/require"
)

const testChainID = "test-chain"

// fakePV signs anything it is asked to, so a refusal in these tests can only come from the retired
// guard rather than from the signing gate.
type fakePV struct {
	key    ed25519.PrivKey
	signed int
}

func newFakePV() *fakePV { return &fakePV{key: ed25519.GenPrivKey()} }

func (f *fakePV) GetPubKey() (crypto.PubKey, error) { return f.key.PubKey(), nil }

func (f *fakePV) SignVote(chainID string, vote *cmtproto.Vote) error {
	f.signed++
	sig, err := f.key.Sign(types.VoteSignBytes(chainID, vote))
	if err != nil {
		return err
	}
	vote.Signature = sig
	return nil
}

func (f *fakePV) SignProposal(chainID string, proposal *cmtproto.Proposal) error {
	f.signed++
	sig, err := f.key.Sign(types.ProposalSignBytes(chainID, proposal))
	if err != nil {
		return err
	}
	proposal.Signature = sig
	return nil
}

func voteRequest() privvalproto.Message {
	return privvalproto.Message{Sum: &privvalproto.Message_SignVoteRequest{
		SignVoteRequest: &privvalproto.SignVoteRequest{
			ChainId: testChainID,
			Vote: &cmtproto.Vote{
				Type:      cmtproto.PrevoteType,
				Height:    10,
				Round:     0,
				Timestamp: time.Now().UTC(),
			},
		},
	}}
}

// TestNodeServerHandleRequestRefusesWhenRetired is the direct guard on the retirement race.
//
// Retiring a connection deletes it from the serving set and stops it asynchronously, but
// SignerServer's service loop never consults that set — so without this check a node removed from
// the target set would keep signing until Stop() landed, long enough to race its replacement for a
// height/round/step reservation.
func TestNodeServerHandleRequestRefusesWhenRetired(t *testing.T) {
	pv := newFakePV()
	ns := &nodeServer{createdAt: time.Now()}
	ns.touch()

	// Before retirement: served normally.
	res, err := ns.handleRequest(pv, voteRequest(), testChainID)
	require.NoError(t, err)
	signed := res.GetSignedVoteResponse()
	require.NotNil(t, signed)
	require.Nil(t, signed.Error, "a live connection must be served")
	require.NotEmpty(t, signed.Vote.Signature)
	require.Equal(t, 1, pv.signed)

	ns.retired.Store(true)

	// After retirement: refused, and the PrivValidator is never reached — so a retired connection
	// cannot reserve a height/round/step out from under its replacement.
	res, err = ns.handleRequest(pv, voteRequest(), testChainID)
	require.Error(t, err, "a retired connection must be refused")
	refused := res.GetSignedVoteResponse()
	require.NotNil(t, refused, "refusal must still be a well-formed response the node can parse")
	require.NotNil(t, refused.Error, "refusal must carry a remote-signer error")
	require.Empty(t, refused.Vote.Signature)
	require.Equal(t, 1, pv.signed, "retired connection must not reach the signer")
}

// TestNodeServerHandleRequestRefusesPubKeyWhenRetired covers the request type that motivated
// refusing via chain ID rather than a bare handler error: on PubKeyRequest a plain error yields an
// empty response message, which the node cannot interpret.
func TestNodeServerHandleRequestRefusesPubKeyWhenRetired(t *testing.T) {
	pv := newFakePV()
	ns := &nodeServer{createdAt: time.Now()}
	ns.touch()
	ns.retired.Store(true)

	req := privvalproto.Message{Sum: &privvalproto.Message_PubKeyRequest{
		PubKeyRequest: &privvalproto.PubKeyRequest{ChainId: testChainID},
	}}
	res, err := ns.handleRequest(pv, req, testChainID)
	require.Error(t, err)
	pubKeyRes := res.GetPubKeyResponse()
	require.NotNil(t, pubKeyRes, "refusal must be a well-formed PubKeyResponse")
	require.NotNil(t, pubKeyRes.Error)
}

// TestNodeServerRetiredDoesNotTouchActivity verifies a retired connection's refusals do not look
// like liveness, so it cannot mask itself as healthy while awaiting teardown.
func TestNodeServerRetiredDoesNotTouchActivity(t *testing.T) {
	pv := newFakePV()
	ns := &nodeServer{createdAt: time.Now()}
	ns.lastActivity.Store(time.Now().Add(-time.Hour).UnixNano())
	ns.retired.Store(true)

	_, _ = ns.handleRequest(pv, voteRequest(), testChainID)
	require.Greater(t, ns.silentFor(), 30*time.Minute,
		"a retired connection's refusals must not register as activity")
}
