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
