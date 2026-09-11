package test

import (
	"crypto/sha256"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
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

type countedBackend struct {
	backend.KeyBackend
	signs atomic.Int32
}

func (b *countedBackend) Sign(signBytes []byte) ([]byte, error) {
	b.signs.Add(1)
	return b.KeyBackend.Sign(signBytes)
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
		NodeID:     "n1",
		BindAddr:   freeAddr(t),
		DataDir:    filepath.Join(dir, "raft"),
		Bootstrap:  true,
		SingleNode: true,
		Insecure:   true,
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
	vote.Extension = []byte("oracle-prices:v1")
	require.NoError(t, sc.SignVote(itestChain, vote))
	require.Equal(t, []byte("oracle-prices:v1"), vote.Extension)
	require.True(t, pub.VerifySignature(types.VoteSignBytes(itestChain, vote), vote.Signature))
	require.True(t, pub.VerifySignature(types.VoteExtensionSignBytes(itestChain, vote), vote.ExtensionSignature))

	proposal := &cmtproto.Proposal{Type: cmtproto.ProposalType, Height: 11, Round: 0, Timestamp: time.Now().UTC()}
	require.NoError(t, sc.SignProposal(itestChain, proposal))
	require.True(t, pub.VerifySignature(types.ProposalSignBytes(itestChain, proposal), proposal.Signature))
}

func TestIntegration_IdempotentResign(t *testing.T) {
	h := newHarness(t, 1)
	defer h.stop()
	sc := h.clients[0]

	ts := time.Date(2026, time.September, 11, 12, 0, 0, 123456789, time.UTC)
	v1 := makeVote(10, 0, ts, "block-A")
	v1.Extension = []byte("first-extension")
	require.NoError(t, sc.SignVote(itestChain, v1))
	sig1 := append([]byte(nil), v1.Signature...)
	extSig1 := append([]byte(nil), v1.ExtensionSignature...)

	v2 := makeVote(10, 0, ts.Add(time.Minute), "block-A")
	v2.Extension = []byte("second-extension")
	require.NoError(t, sc.SignVote(itestChain, v2))
	require.Equal(t, sig1, v2.Signature, "re-signing identical vote must return the same signature")
	require.Equal(t, ts, v2.Timestamp, "re-signing must restore the reserved canonical timestamp")
	require.NotEqual(t, extSig1, v2.ExtensionSignature, "the changed extension must receive a new signature")
	require.True(t, h.pub.VerifySignature(types.VoteExtensionSignBytes(itestChain, v2), v2.ExtensionSignature))
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

func TestIntegration_IndependentRaftHistoriesCannotUseSameSoftwareKey(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "priv_validator_key.json")
	filePV := privval.GenFilePV(keyFile, filepath.Join(dir, "priv_validator_state.json"))
	filePV.Key.Save()

	newIndependentHistory := func(nodeID string) (*countedBackend, state.StateStore) {
		be, err := backend.NewSoftware(keyFile)
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, be.Close()) })
		counted := &countedBackend{KeyBackend: be}

		store, err := state.NewRaftStore(state.RaftConfig{
			NodeID:     nodeID,
			BindAddr:   freeAddr(t),
			DataDir:    filepath.Join(dir, nodeID),
			Bootstrap:  true,
			SingleNode: true,
			Insecure:   true,
		}, hclog.NewNullLogger())
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, store.Close()) })
		require.Eventually(t, store.IsLeader, 10*time.Second, 50*time.Millisecond)

		return counted, store
	}

	backendA, storeA := newIndependentHistory("cluster-a")
	backendB, storeB := newIndependentHistory("cluster-b")
	clusterA, err := storeA.EnsureClusterID(t.Context())
	require.NoError(t, err)
	clusterB, err := storeB.EnsureClusterID(t.Context())
	require.NoError(t, err)
	require.NotEqual(t, clusterA, clusterB)
	require.NoError(t, backendA.ClaimCluster(t.Context(), clusterA))
	require.NoError(t, backend.RequireClusterBinding(t.Context(), backendA, clusterA))
	pvA, err := signer.New(backendA, storeA)
	require.NoError(t, err)
	ts := time.Now().UTC()
	require.NoError(t, pvA.SignVote(itestChain, makeVote(10, 0, ts, "block-A")))

	err = backend.RequireClusterBinding(t.Context(), backendB, clusterB)
	require.ErrorIs(t, err, backend.ErrBindingMismatch)
	require.Zero(t, backendB.signs.Load(), "independent history must be refused before any backend or preflight signature")
}
