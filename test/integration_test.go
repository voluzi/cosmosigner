package test

import (
	"crypto/sha256"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/crypto/ed25519"
	cmtlog "github.com/cometbft/cometbft/libs/log"
	"github.com/cometbft/cometbft/privval"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cometbft/cometbft/types"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"

	"github.com/voluzi/cosmosigner/internal/backend"
	"github.com/voluzi/cosmosigner/internal/signer"
	"github.com/voluzi/cosmosigner/internal/state"
)

const itestChain = "itest-chain"

type harness struct {
	pub       crypto.PubKey
	store     state.StateStore
	clients   []*privval.SignerClient
	servers   []*privval.SignerServer
	listeners []*privval.SignerListenerEndpoint
}

func (h *harness) stop() {
	for _, ss := range h.servers {
		_ = ss.Stop()
	}
	for _, sl := range h.listeners {
		_ = sl.Stop()
	}
	_ = h.store.Close()
}

func newHarness(t *testing.T, nodes int) *harness {
	t.Helper()
	dir := t.TempDir()
	priv := ed25519.GenPrivKey()
	be := backend.NewSoftwareFromPriv(priv)

	store, err := state.NewRaftStore(state.RaftConfig{
		NodeID:    "n1",
		BindAddr:  freeAddr(t),
		DataDir:   filepath.Join(dir, "raft"),
		Bootstrap: true,
	}, hclog.NewNullLogger())
	require.NoError(t, err)
	require.Eventually(t, store.IsLeader, 10*time.Second, 50*time.Millisecond, "raft did not elect a leader")

	pv, err := signer.New(be, store)
	require.NoError(t, err)
	pub, err := be.PubKey()
	require.NoError(t, err)

	logger := cmtlog.NewNopLogger()
	connKey := ed25519.GenPrivKey()
	h := &harness{pub: pub, store: store}

	for range nodes {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		// The node side must also speak SecretConnection; wrap the raw listener.
		tcpLn := privval.NewTCPListener(ln, ed25519.GenPrivKey())
		sl := privval.NewSignerListenerEndpoint(logger, tcpLn,
			privval.SignerListenerEndpointTimeoutReadWrite(5*time.Second))
		require.NoError(t, sl.Start())

		sd := privval.NewSignerDialerEndpoint(logger,
			privval.DialTCPFn(ln.Addr().String(), 5*time.Second, connKey),
			privval.SignerDialerEndpointConnRetries(50),
		)
		ss := privval.NewSignerServer(sd, itestChain, pv)
		require.NoError(t, ss.Start())

		sc, err := privval.NewSignerClient(sl, itestChain)
		require.NoError(t, err)

		h.listeners = append(h.listeners, sl)
		h.servers = append(h.servers, ss)
		h.clients = append(h.clients, sc)
	}
	return h
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	return ln.Addr().String()
}

func hash32(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

func makeVote(height int64, round int32, ts time.Time, block string) *cmtproto.Vote {
	return &cmtproto.Vote{
		Type:   cmtproto.PrecommitType,
		Height: height,
		Round:  round,
		BlockID: cmtproto.BlockID{
			Hash:          hash32(block),
			PartSetHeader: cmtproto.PartSetHeader{Total: 1, Hash: hash32(block + "-parts")},
		},
		Timestamp: ts,
	}
}

func TestIntegration_SignAndVerify(t *testing.T) {
	h := newHarness(t, 1)
	defer h.stop()
	sc := h.clients[0]

	pub, err := sc.GetPubKey()
	require.NoError(t, err)
	require.Equal(t, h.pub.Bytes(), pub.Bytes())

	vote := makeVote(10, 0, time.Now().UTC(), "block-A")
	require.NoError(t, sc.SignVote(itestChain, vote))
	require.True(t, pub.VerifySignature(types.VoteSignBytes(itestChain, vote), vote.Signature))

	proposal := &cmtproto.Proposal{Type: cmtproto.ProposalType, Height: 11, Round: 0, Timestamp: time.Now().UTC()}
	require.NoError(t, sc.SignProposal(itestChain, proposal))
	require.True(t, pub.VerifySignature(types.ProposalSignBytes(itestChain, proposal), proposal.Signature))
}

func TestIntegration_IdempotentResign(t *testing.T) {
	h := newHarness(t, 1)
	defer h.stop()
	sc := h.clients[0]

	ts := time.Now().UTC()
	v1 := makeVote(10, 0, ts, "block-A")
	require.NoError(t, sc.SignVote(itestChain, v1))
	sig1 := append([]byte(nil), v1.Signature...)

	v2 := makeVote(10, 0, ts, "block-A")
	require.NoError(t, sc.SignVote(itestChain, v2))
	require.Equal(t, sig1, v2.Signature, "re-signing identical vote must return the same signature")
}

func TestIntegration_RegressionRefused(t *testing.T) {
	h := newHarness(t, 1)
	defer h.stop()
	sc := h.clients[0]

	require.NoError(t, sc.SignVote(itestChain, makeVote(10, 0, time.Now().UTC(), "A")))
	err := sc.SignVote(itestChain, makeVote(9, 0, time.Now().UTC(), "B"))
	require.Error(t, err, "signing a lower height must be refused")
}

func TestIntegration_ConflictRefused(t *testing.T) {
	h := newHarness(t, 1)
	defer h.stop()
	sc := h.clients[0]

	require.NoError(t, sc.SignVote(itestChain, makeVote(10, 0, time.Now().UTC(), "block-A")))
	err := sc.SignVote(itestChain, makeVote(10, 0, time.Now().UTC(), "block-B"))
	require.Error(t, err, "signing a different block at the same height/round/step must be refused")
}

// TestIntegration_MultiNodeConsistent verifies the horcrux-style model: two
// independent node connections to one signer, signing the same height
// concurrently, get one consistent signature — and losing a node doesn't stop
// the others.
func TestIntegration_MultiNodeConsistent(t *testing.T) {
	h := newHarness(t, 2)
	defer h.stop()

	ts := time.Now().UTC()
	v0 := makeVote(10, 0, ts, "block-A")
	v1 := makeVote(10, 0, ts, "block-A")

	var wg sync.WaitGroup
	errs := make([]error, 2)
	wg.Add(2)
	go func() { defer wg.Done(); errs[0] = h.clients[0].SignVote(itestChain, v0) }()
	go func() { defer wg.Done(); errs[1] = h.clients[1].SignVote(itestChain, v1) }()
	wg.Wait()

	require.NoError(t, errs[0])
	require.NoError(t, errs[1])
	require.Equal(t, v0.Signature, v1.Signature, "both nodes must obtain the same signature for the same height")
	require.True(t, h.pub.VerifySignature(types.VoteSignBytes(itestChain, v0), v0.Signature))

	// A conflicting block at the same height/round/step is refused on either node.
	require.Error(t, h.clients[1].SignVote(itestChain, makeVote(10, 0, ts, "block-B")))

	// Lose one node; the other keeps signing the next height.
	_ = h.servers[0].Stop()
	_ = h.listeners[0].Stop()
	require.NoError(t, h.clients[1].SignVote(itestChain, makeVote(11, 0, time.Now().UTC(), "block-C")))
}
