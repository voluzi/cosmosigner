package server

import (
	"testing"
	"time"

	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/crypto/ed25519"
	cmtlog "github.com/cometbft/cometbft/libs/log"
	"github.com/cometbft/cometbft/privval"
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

// TestNeedsFastDiscoveryAfterRetirement covers the multi-node replacement case: when a node dies and
// DNS drops it, the dead address is retired out of the serving set entirely, leaving only healthy
// connections. Liveness alone would then stop driving discovery — so a replacement address published
// moments later would wait out the full ReconcileInterval.
//
// The post-retirement window is what keeps discovery fast across that gap.
func TestNeedsFastDiscoveryAfterRetirement(t *testing.T) {
	newLifecycle := func() *Lifecycle {
		return New(Config{
			ChainID:           testChainID,
			ReconcileInterval: 30 * time.Second,
			StaleConnTimeout:  30 * time.Second,
		}, StaticNodes{}, newFakePV(), ed25519.GenPrivKey(), nil, cmtlog.NewNopLogger())
	}

	t.Run("quiet when nothing is pending", func(t *testing.T) {
		l := newLifecycle()
		require.False(t, l.needsFastDiscovery(), "an empty serving set needs no fast discovery")
	})

	t.Run("fast for a bounded window after a retirement", func(t *testing.T) {
		l := newLifecycle()
		// A real (never-started) SignerServer: retire() calls Stop() on it, which must not panic.
		addr := "127.0.0.1:5555"
		ep := privval.NewSignerDialerEndpoint(cmtlog.NewNopLogger(),
			privval.DialTCPFn(addr, time.Second, ed25519.GenPrivKey()))
		ns := &nodeServer{
			srv:       privval.NewSignerServer(ep, testChainID, newFakePV()),
			ep:        ep,
			createdAt: time.Now(),
		}
		ns.touch()
		l.servers[addr] = ns

		l.mu.Lock()
		l.retire(addr, ns)
		l.mu.Unlock()
		l.stopping.Wait()

		// The dead address is gone and nothing unhealthy remains, yet the replacement may still be
		// unpublished — discovery must stay fast.
		require.Empty(t, l.servers, "retired address must leave the serving set")
		require.True(t, l.needsFastDiscovery(), "discovery must stay fast while a replacement may be pending")

		// Bounded: it lapses rather than polling forever.
		l.mu.Lock()
		l.discoveryPendingUntil = time.Now().Add(-time.Second)
		l.mu.Unlock()
		require.False(t, l.needsFastDiscovery(), "the window must lapse once the replacement window expires")
	})

	t.Run("window is bounded by the reconcile interval", func(t *testing.T) {
		l := newLifecycle()
		require.Equal(t, 30*time.Second, l.discoveryPendingWindow())

		short := New(Config{ChainID: testChainID, ReconcileInterval: 2 * time.Second},
			StaticNodes{}, newFakePV(), ed25519.GenPrivKey(), nil, cmtlog.NewNopLogger())
		require.Equal(t, 2*time.Second, short.discoveryPendingWindow(),
			"a short interval must not be extended by the window")
	})
}
