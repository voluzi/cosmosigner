package test

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/cometbft/cometbft/crypto/ed25519"
	cmtlog "github.com/cometbft/cometbft/libs/log"
	"github.com/cometbft/cometbft/libs/protoio"
	p2pconn "github.com/cometbft/cometbft/p2p/conn"
	"github.com/cometbft/cometbft/privval"
	privvalproto "github.com/cometbft/cometbft/proto/tendermint/privval"
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
		NodeID:     "n1",
		BindAddr:   freeAddr(t),
		DataDir:    filepath.Join(dir, "raft"),
		Bootstrap:  true,
		SingleNode: true,
		Insecure:   true,
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
	//
	// The budget is generous on purpose: a dropped node stops being served only once cometbft's
	// endpoint notices the closed socket, which is EOF-driven and takes ~1.3s locally (unchanged by
	// the reconcile interval). A loaded CI runner is slower still, so a tight bound here fails for
	// timing rather than for behaviour.
	src.set(addrB)
	require.Eventually(t, func() bool {
		return clientA.SignVote(itestChain, makeVote(12, 0, time.Now().UTC(), "A")) != nil
	}, 20*time.Second, 200*time.Millisecond, "removed node should lose its signer connection")
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
		NodeID:     "n1",
		BindAddr:   freeAddr(t),
		DataDir:    filepath.Join(dir, "raft"),
		Bootstrap:  true,
		SingleNode: true,
		Insecure:   true,
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
		NodeID:     "n1",
		BindAddr:   freeAddr(t),
		DataDir:    filepath.Join(dir, "raft"),
		Bootstrap:  true,
		SingleNode: true,
		Insecure:   true,
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
// keeps dialing it and is never retired on its own, so discovery would go quiet and leave the
// periodic tick to find the replacement. ReconcileInterval is set to 30s, far beyond the assertion
// window, so this passes only if discovery keeps re-resolving while a connector is unconnected.
func TestDiscovery_ReplacementAddressAppearsAfterWake(t *testing.T) {
	dir := t.TempDir()
	be := backend.NewSoftwareFromPriv(ed25519.GenPrivKey())
	store, err := state.NewRaftStore(state.RaftConfig{
		NodeID:     "n1",
		BindAddr:   freeAddr(t),
		DataDir:    filepath.Join(dir, "raft"),
		Bootstrap:  true,
		SingleNode: true,
		Insecure:   true,
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

// TestDiscovery_NodeListensLongAfterDialStart proves a connector never gives up: a node that starts
// listening long after dialing began is served by the connector that was created for it.
//
// ReconcileInterval and StaleConnTimeout are far beyond the test, so nothing recreates the
// connector. If its dial loop had ended, the address would stay unserved.
func TestDiscovery_NodeListensLongAfterDialStart(t *testing.T) {
	dir := t.TempDir()
	be := backend.NewSoftwareFromPriv(ed25519.GenPrivKey())
	store, err := state.NewRaftStore(state.RaftConfig{
		NodeID:     "n1",
		BindAddr:   freeAddr(t),
		DataDir:    filepath.Join(dir, "raft"),
		Bootstrap:  true,
		SingleNode: true,
		Insecure:   true,
	}, hclog.NewNullLogger())
	require.NoError(t, err)
	defer store.Close()
	require.Eventually(t, store.IsLeader, 10*time.Second, 50*time.Millisecond)

	pv, err := signer.New(be, store)
	require.NoError(t, err)
	pub, err := be.PubKey()
	require.NoError(t, err)

	addr := freeAddr(t)
	lc := server.New(server.Config{
		ChainID:           itestChain,
		ReconcileInterval: time.Minute,
		StaleConnTimeout:  time.Minute,
		RetryWait:         10 * time.Millisecond,
	}, server.StaticNodes{addr}, pv, ed25519.GenPrivKey(), store, cmtlog.NewNopLogger())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = lc.Run(ctx) }()

	// Hundreds of refused dials: far more than any fixed retry count the endpoint would allow.
	time.Sleep(3 * time.Second)

	ln, err := net.Listen("tcp", addr)
	require.NoError(t, err)
	sl := privval.NewSignerListenerEndpoint(cmtlog.NewNopLogger(),
		privval.NewTCPListener(ln, ed25519.GenPrivKey()),
		privval.SignerListenerEndpointTimeoutReadWrite(2*time.Second))
	require.NoError(t, sl.Start())
	defer func() { _ = sl.Stop() }()

	// No retry here on purpose. A starting node asks for the public key once, waits 3s for a signer
	// to connect (cometbft's accept timeout, which this listener shares) and exits if none does.
	client, err := privval.NewSignerClient(sl, itestChain)
	require.NoError(t, err)
	got, err := client.GetPubKey()
	require.NoError(t, err, "the connector must still be dialing when the node starts listening")
	require.Equal(t, pub.Bytes(), got.Bytes())
}

// startRetirementTest runs a lifecycle against one address that the returned source can drop.
func startRetirementTest(t *testing.T, addr string, timeoutReadWrite time.Duration) (*mutableNodes, *server.Lifecycle) {
	t.Helper()
	be := backend.NewSoftwareFromPriv(ed25519.GenPrivKey())
	store, err := state.NewRaftStore(state.RaftConfig{
		NodeID:     "n1",
		BindAddr:   freeAddr(t),
		DataDir:    filepath.Join(t.TempDir(), "raft"),
		Bootstrap:  true,
		SingleNode: true,
		Insecure:   true,
	}, hclog.NewNullLogger())
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	require.Eventually(t, store.IsLeader, 10*time.Second, 50*time.Millisecond)

	pv, err := signer.New(be, store)
	require.NoError(t, err)

	src := &mutableNodes{}
	src.set(addr)
	lc := server.New(server.Config{
		ChainID:           itestChain,
		ReconcileInterval: 100 * time.Millisecond,
		TimeoutReadWrite:  timeoutReadWrite,
		RetryWait:         10 * time.Millisecond,
	}, src, pv, ed25519.GenPrivKey(), store, cmtlog.NewNopLogger())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = lc.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return src, lc
}

// TestDiscovery_RetiredConnectorStopsDialing proves a connector dropped from the target set stops
// dialing. A node accepts one signer at a time, so a retired connector that kept dialing could take
// that slot and refuse every request on it.
func TestDiscovery_RetiredConnectorStopsDialing(t *testing.T) {
	// A plain TCP listener stands in for the node: it never completes the handshake, so the
	// connector is permanently mid-dial, the state cometbft's Stop() does not interrupt.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	tcpLn := ln.(*net.TCPListener)
	accept := func(wait time.Duration) bool {
		require.NoError(t, tcpLn.SetDeadline(time.Now().Add(wait)))
		conn, err := tcpLn.Accept()
		if err != nil {
			return false
		}
		_ = conn.Close()
		return true
	}

	src, _ := startRetirementTest(t, ln.Addr().String(), time.Second)
	for range 3 {
		require.True(t, accept(10*time.Second), "the connector must redial while the node is in the target set")
	}

	src.set()

	// Dials already in flight may still land; after that the listener must stay quiet. The quiet
	// window is 100 times the 10ms retry wait, so a connector that is still dialing cannot fit a
	// silence that long, while a slow machine only makes the silence easier to observe.
	require.Eventually(t, func() bool { return !accept(time.Second) }, 20*time.Second, time.Millisecond,
		"a retired connector must stop dialing")
}

// TestDiscovery_RetiredConnectorNeverAnswers proves the node gets no response from a connector
// once it is retired, whatever stage its connection had reached. The node holds one signer
// connection and takes a refusal as that signer's answer, so the connection must be closed instead:
// a node that has just started listening exits on a refused public-key request.
func TestDiscovery_RetiredConnectorNeverAnswers(t *testing.T) {
	for _, tc := range []struct {
		name string
		// established completes the handshake before retirement, so the connector is retired while
		// reading from a live connection. Otherwise the node holds the handshake until after.
		established bool
	}{
		{name: "handshake pending at retirement"},
		{name: "connection established before retirement", established: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			defer ln.Close()
			addr := ln.Addr().String()

			// The read/write timeout is far beyond the test, so only retirement can close the socket.
			src, lc := startRetirementTest(t, addr, time.Minute)

			// Whether a connector that outlives its retirement gets to answer depends on scheduling, so
			// the node is dropped and added back several times: each round retires a fresh connector.
			for range 8 {
				requireNoAnswerAfterRetirement(t, ln, src, lc, tc.established)
				src.set(addr)
			}
		})
	}
}

// requireNoAnswerAfterRetirement accepts the connector's dial as the node, drops the node from the
// target set and requires that a public-key request sent afterwards is not answered.
func requireNoAnswerAfterRetirement(t *testing.T, ln net.Listener, src *mutableNodes, lc *server.Lifecycle, established bool) {
	t.Helper()
	// Accept and stay silent: the connector blocks waiting for the node's half of the handshake.
	conn, err := ln.Accept()
	require.NoError(t, err)
	defer conn.Close()
	// The deadline only bounds a failing run; a passing one returns as soon as the peer closes.
	require.NoError(t, conn.SetDeadline(time.Now().Add(20*time.Second)))
	nodeKey := ed25519.GenPrivKey()

	var secret net.Conn
	roundTrip := func(req privvalproto.Message) (privvalproto.Message, error) {
		var res privvalproto.Message
		if _, err := protoio.NewDelimitedWriter(secret).WriteMsg(&req); err != nil {
			return res, err
		}
		_, err := protoio.NewDelimitedReader(secret, 10*1024).ReadMsg(&res)
		return res, err
	}
	ping := privvalproto.Message{Sum: &privvalproto.Message_PingRequest{PingRequest: &privvalproto.PingRequest{}}}

	if established {
		secret, err = p2pconn.MakeSecretConnection(conn, nodeKey)
		require.NoError(t, err)
		_, err = roundTrip(ping)
		require.NoError(t, err, "the connector must serve before it is retired")
	}
	require.Eventually(t, func() bool { return len(lc.Status()) == 1 }, 10*time.Second, 10*time.Millisecond)

	src.set()
	retired := func() bool { return len(lc.Status()) == 0 }
	if established {
		// Keep pinging as a node does: the connector's read holds the endpoint lock that a reconcile
		// waits behind, so a silent connection would stall the retirement itself.
		for err == nil && !retired() {
			_, err = roundTrip(ping)
			time.Sleep(10 * time.Millisecond)
		}
	}
	require.Eventually(t, retired, 10*time.Second, 10*time.Millisecond)

	if !established {
		secret, err = p2pconn.MakeSecretConnection(conn, nodeKey)
	}
	var res privvalproto.Message
	if err == nil {
		res, err = roundTrip(privvalproto.Message{Sum: &privvalproto.Message_PubKeyRequest{
			PubKeyRequest: &privvalproto.PubKeyRequest{ChainId: itestChain},
		}})
	}

	require.Error(t, err, "a retired connector must not answer, got %v", &res)
	// A timeout means the connector still holds the socket.
	var netErr net.Error
	require.False(t, errors.As(err, &netErr) && netErr.Timeout(),
		"retirement must close the connection: %v", err)
}
