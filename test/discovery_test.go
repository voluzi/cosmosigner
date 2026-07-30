package test

import (
	"context"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/cometbft/cometbft/crypto/ed25519"
	cmtlog "github.com/cometbft/cometbft/libs/log"
	"github.com/cometbft/cometbft/privval"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"

	"github.com/voluzi/cosmosigner/internal/backend"
	"github.com/voluzi/cosmosigner/internal/server"
	"github.com/voluzi/cosmosigner/internal/signer"
	"github.com/voluzi/cosmosigner/internal/state"
)

// mutableNodes is a NodeSource whose address set can change at runtime,
// simulating headless-service discovery.
type mutableNodes struct {
	mu    sync.Mutex
	addrs []string
}

func (m *mutableNodes) set(addrs ...string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.addrs = addrs
}

func (m *mutableNodes) Nodes() ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.addrs...), nil
}

func (m *mutableNodes) Describe() string { return "mutable" }

func startNodeListener(t *testing.T) (*privval.SignerListenerEndpoint, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	sl := privval.NewSignerListenerEndpoint(cmtlog.NewNopLogger(),
		privval.NewTCPListener(ln, ed25519.GenPrivKey()),
		privval.SignerListenerEndpointTimeoutReadWrite(2*time.Second))
	require.NoError(t, sl.Start())
	return sl, addr
}

// TestDiscovery_DynamicNodeSet proves the lifecycle adds and drops node
// connections live as the NodeSource changes — the headless-service model.
func TestDiscovery_DynamicNodeSet(t *testing.T) {
	dir := t.TempDir()
	be := backend.NewSoftwareFromPriv(ed25519.GenPrivKey())
	store, err := state.NewRaftStore(state.RaftConfig{
		NodeID:    "n1",
		BindAddr:  freeAddr(t),
		DataDir:   filepath.Join(dir, "raft"),
		Bootstrap: true,
	}, hclog.NewNullLogger())
	require.NoError(t, err)
	defer store.Close()
	require.Eventually(t, store.IsLeader, 10*time.Second, 50*time.Millisecond)

	pv, err := signer.New(be, store)
	require.NoError(t, err)

	slA, addrA := startNodeListener(t)
	slB, addrB := startNodeListener(t)

	src := &mutableNodes{}
	src.set(addrA)

	lc := server.New(server.Config{
		ChainID:           itestChain,
		ReconcileInterval: 200 * time.Millisecond,
	}, src, pv, ed25519.GenPrivKey(), store, cmtlog.NewNopLogger())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = lc.Run(ctx) }()

	// Node A is in the set: it should get a signer and be able to sign.
	clientA, err := privval.NewSignerClient(slA, itestChain)
	require.NoError(t, err)
	require.NoError(t, clientA.SignVote(itestChain, makeVote(10, 0, time.Now().UTC(), "A")))

	// Add node B → it should be discovered and become servable.
	src.set(addrA, addrB)
	clientB, err := privval.NewSignerClient(slB, itestChain)
	require.NoError(t, err)
	require.NoError(t, clientB.SignVote(itestChain, makeVote(11, 0, time.Now().UTC(), "B")))

	// Drop node A → its connection should be torn down; B keeps working.
	src.set(addrB)
	require.Eventually(t, func() bool {
		return clientA.SignVote(itestChain, makeVote(12, 0, time.Now().UTC(), "A")) != nil
	}, 6*time.Second, 200*time.Millisecond, "removed node should lose its signer connection")
	require.NoError(t, clientB.SignVote(itestChain, makeVote(13, 0, time.Now().UTC(), "B")))

	_ = slA.Stop()
	_ = slB.Stop()
}

// TestDiscovery_NodeAppearsAfterDialTimeout is a regression test: a node that
// only becomes reachable AFTER the connector has been dialing longer than
// StaleConnTimeout must still connect and stay connected. (A bug recycled the
// connector the instant it connected, killing the handshake before the first
// request — breaking any node that took >StaleConnTimeout to come up.)
func TestDiscovery_NodeAppearsAfterDialTimeout(t *testing.T) {
	dir := t.TempDir()
	be := backend.NewSoftwareFromPriv(ed25519.GenPrivKey())
	store, err := state.NewRaftStore(state.RaftConfig{
		NodeID:    "n1",
		BindAddr:  freeAddr(t),
		DataDir:   filepath.Join(dir, "raft"),
		Bootstrap: true,
	}, hclog.NewNullLogger())
	require.NoError(t, err)
	defer store.Close()
	require.Eventually(t, store.IsLeader, 10*time.Second, 50*time.Millisecond)

	pv, err := signer.New(be, store)
	require.NoError(t, err)

	// Pre-choose an address but do NOT listen yet — the connector will dial a
	// dead address for a while.
	addr := freeAddr(t)

	lc := server.New(server.Config{
		ChainID:           itestChain,
		ReconcileInterval: 200 * time.Millisecond,
		StaleConnTimeout:  500 * time.Millisecond, // short, to exercise the bug fast
	}, server.StaticNodes{addr}, pv, ed25519.GenPrivKey(), store, cmtlog.NewNopLogger())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = lc.Run(ctx) }()

	// Dial the dead address for well over StaleConnTimeout.
	time.Sleep(2 * time.Second)

	// Now bring the node up on that exact address.
	ln, err := net.Listen("tcp", addr)
	require.NoError(t, err)
	sl := privval.NewSignerListenerEndpoint(cmtlog.NewNopLogger(),
		privval.NewTCPListener(ln, ed25519.GenPrivKey()),
		privval.SignerListenerEndpointTimeoutReadWrite(2*time.Second))
	require.NoError(t, sl.Start())
	defer func() { _ = sl.Stop() }()

	// The connector must connect and serve — not be recycled mid-handshake.
	client, err := privval.NewSignerClient(sl, itestChain)
	require.NoError(t, err)
	require.NoError(t, client.SignVote(itestChain, makeVote(10, 0, time.Now().UTC(), "A")))
	// And keep serving a moment later (proves it wasn't recycled right after).
	time.Sleep(1 * time.Second)
	require.NoError(t, client.SignVote(itestChain, makeVote(11, 0, time.Now().UTC(), "A")))
}

// TestDiscovery_NodeReplacedAtNewAddress reproduces the rendezvous loop from cosmopilot#66: a node
// pod dies and is recreated at a NEW address, so the signer's resolved target is stale the moment
// it is resolved. Retiring the dead connection must not block the reconcile behind a multi-second
// srv.Stop(), and must wake discovery instead of waiting out the tick.
//
// The reconcile interval is deliberately long here: if rendezvous only happened on the tick, this
// test would time out. Passing it proves the retire path drives the recovery.
func TestDiscovery_NodeReplacedAtNewAddress(t *testing.T) {
	dir := t.TempDir()
	be := backend.NewSoftwareFromPriv(ed25519.GenPrivKey())
	store, err := state.NewRaftStore(state.RaftConfig{
		NodeID:    "n1",
		BindAddr:  freeAddr(t),
		DataDir:   filepath.Join(dir, "raft"),
		Bootstrap: true,
	}, hclog.NewNullLogger())
	require.NoError(t, err)
	defer store.Close()
	require.Eventually(t, store.IsLeader, 10*time.Second, 50*time.Millisecond)

	pv, err := signer.New(be, store)
	require.NoError(t, err)

	slOld, addrOld := startNodeListener(t)
	src := &mutableNodes{}
	src.set(addrOld)

	lc := server.New(server.Config{
		ChainID: itestChain,
		// Far longer than the assertions below: recovery must not depend on it.
		ReconcileInterval: 30 * time.Second,
		StaleConnTimeout:  500 * time.Millisecond,
	}, src, pv, ed25519.GenPrivKey(), store, cmtlog.NewNopLogger())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = lc.Run(ctx) }()

	clientOld, err := privval.NewSignerClient(slOld, itestChain)
	require.NoError(t, err)
	require.NoError(t, clientOld.SignVote(itestChain, makeVote(10, 0, time.Now().UTC(), "A")))

	// The node dies and comes back at a different address, exactly as a recreated pod does.
	_ = slOld.Stop()
	slNew, addrNew := startNodeListener(t)
	defer func() { _ = slNew.Stop() }()
	require.NotEqual(t, addrOld, addrNew)
	src.set(addrNew)

	clientNew, err := privval.NewSignerClient(slNew, itestChain)
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		return clientNew.SignVote(itestChain, makeVote(11, 0, time.Now().UTC(), "A")) == nil
	}, 20*time.Second, 200*time.Millisecond,
		"replaced node must be served well before the reconcile tick")
}

// TestDiscovery_ReplacementAddressAppearsAfterWake covers the DNS-lag case: the node is replaced,
// but the resolved set still returns only the DEAD address at the moment of the teardown wake. The
// replacement record shows up shortly after.
//
// A one-shot wake is not enough here — reconcile recreates a connector for the stale address, which
// is not "exhausted" for MaxRetries×RetryWait (~10min), so discovery would go quiet and leave the
// periodic tick to find the replacement. ReconcileInterval is set to 30s, far beyond the assertion
// window, so this passes only if discovery keeps re-resolving while a connector is unconnected.
func TestDiscovery_ReplacementAddressAppearsAfterWake(t *testing.T) {
	dir := t.TempDir()
	be := backend.NewSoftwareFromPriv(ed25519.GenPrivKey())
	store, err := state.NewRaftStore(state.RaftConfig{
		NodeID:    "n1",
		BindAddr:  freeAddr(t),
		DataDir:   filepath.Join(dir, "raft"),
		Bootstrap: true,
	}, hclog.NewNullLogger())
	require.NoError(t, err)
	defer store.Close()
	require.Eventually(t, store.IsLeader, 10*time.Second, 50*time.Millisecond)

	pv, err := signer.New(be, store)
	require.NoError(t, err)

	slOld, addrOld := startNodeListener(t)
	src := &mutableNodes{}
	src.set(addrOld)

	lc := server.New(server.Config{
		ChainID:           itestChain,
		ReconcileInterval: 30 * time.Second, // must not be what rescues this
		StaleConnTimeout:  500 * time.Millisecond,
	}, src, pv, ed25519.GenPrivKey(), store, cmtlog.NewNopLogger())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = lc.Run(ctx) }()

	clientOld, err := privval.NewSignerClient(slOld, itestChain)
	require.NoError(t, err)
	require.NoError(t, clientOld.SignVote(itestChain, makeVote(10, 0, time.Now().UTC(), "A")))

	// Node dies. DNS still advertises only the dead address, so the wake after teardown re-resolves
	// to a stale target and builds a connector that will never connect.
	_ = slOld.Stop()
	time.Sleep(2 * time.Second)

	// Only now does the replacement record appear.
	slNew, addrNew := startNodeListener(t)
	defer func() { _ = slNew.Stop() }()
	require.NotEqual(t, addrOld, addrNew)
	src.set(addrNew)

	clientNew, err := privval.NewSignerClient(slNew, itestChain)
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		return clientNew.SignVote(itestChain, makeVote(11, 0, time.Now().UTC(), "A")) == nil
	}, 15*time.Second, 200*time.Millisecond,
		"discovery must keep re-resolving until the replacement address is served")
}
