package server

import (
	"context"
	"errors"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cometbft/cometbft/crypto"
	cmtlog "github.com/cometbft/cometbft/libs/log"
	cmtnet "github.com/cometbft/cometbft/libs/net"
	p2pconn "github.com/cometbft/cometbft/p2p/conn"
	"github.com/cometbft/cometbft/privval"
	privvalproto "github.com/cometbft/cometbft/proto/tendermint/privval"
	"github.com/cometbft/cometbft/types"

	"github.com/voluzi/cosmosigner/internal/state"
)

// Config configures the privval connection lifecycle.
type Config struct {
	ChainID          string
	TimeoutReadWrite time.Duration
	// RetryWait is the pause between failed dials. A connector dials until it is
	// retired, so a (re)starting node always finds cosmosigner dialing, and this
	// plus dialTimeout bounds how long a node that just started listening waits.
	RetryWait         time.Duration
	ReconcileInterval time.Duration // how often to re-resolve nodes / re-check leadership
	// StaleConnTimeout recycles a node connection with no inbound activity for
	// this long. A healthy node pings every ~3s, so silence on a *connected*
	// socket means the link is dead in a way cometbft's endpoint cannot recover
	// from by itself (see nodeServer). Must comfortably exceed the ping interval.
	StaleConnTimeout time.Duration
}

// dialTimeout bounds one TCP connect attempt. Without it a dial to an address whose SYNs are
// dropped (a pod whose network is not programmed yet) follows the kernel's retransmit backoff, and
// a node that starts listening in the meantime waits that out instead of RetryWait.
const dialTimeout = time.Second

var errConnectorRetired = errors.New("connector retired")

// nodeServer is one node's signer connection with its activity timestamp.
//
// Two things are needed on top of cometbft's SignerServer:
//
//   - Dead-but-"connected" socket: cometbft's signerEndpoint only drops its
//     connection on read/write TIMEOUTS. If the node closes the TCP connection
//     (restart/crash), reads return EOF, the endpoint still reports IsConnected,
//     and the service loop spins on EOF without re-dialing. Detected as a
//     *connected* socket that has gone silent past StaleConnTimeout, which
//     triggers a recreate on the reconcile tick.
//   - Dialing: cometbft's dial loop gives up after a fixed number of attempts and
//     never looks at whether the server was stopped. The retry loop therefore
//     lives in dial, which keeps going until the connector is retired and stops
//     as soon as it is.
type nodeServer struct {
	srv          *privval.SignerServer
	ep           *privval.SignerDialerEndpoint
	addr         string
	connected    bool         // last observed connection state (reconcile-only)
	lastActivity atomic.Int64 // unix nanos of the last handled request (pings included)
	// retired marks this connection as no longer serving. It is set synchronously when the
	// connection is dropped from the serving set, before the (blocking) Stop() runs — see retire.
	retired atomic.Bool
	// dialCtx is cancelled by retire, which aborts an in-flight connect and the wait between dials.
	dialCtx  context.Context
	stopDial context.CancelFunc

	connMu sync.Mutex
	// conn is the socket most recently opened by dial, kept so retirement can close it whatever
	// stage it reached. Guarded by connMu.
	conn net.Conn
}

func (ns *nodeServer) touch() { ns.lastActivity.Store(time.Now().UnixNano()) }

// handleRequest serves one privval request, recording inbound activity (pings included) for
// dead-socket detection.
//
// A retired connection must not serve, even before its asynchronous Stop() has landed: the
// SignerServer service loop does not consult the serving set, and a request it had already read
// when retirement closed the socket still reaches this handler. This check is what keeps such a
// request from signing. Without it, a node removed from the target set could race its replacement
// for a height/round/step reservation.
//
// The check is not a drain: a request that has already passed it runs to completion (bounded by the
// backend signing call) even as the replacement connection starts, because neither closing the
// socket nor SignerServer.Stop() waits for in-flight handlers. Its reply is lost with the socket, so
// the node asks again on its next connection. That residual overlap is safe rather than merely
// unlikely — both
// connections share one GatedPrivValidator, so both reserve through raft, and fsm.applyReserve is
// total over the H/R/S comparison: identical signBytes reuse the cached signature (or re-sign
// deterministically), a timestamp-only difference signs the *reserved* bytes, and anything else at
// the same H/R/S is refused with ErrConflict. Ordering is decided by the raft log, not by goroutine
// scheduling. So the overlap can cost one retried request, which gets the reserved bytes back,
// never a second distinct signature at one H/R/S. Draining would mean blocking replacement creation on an in-flight count —
// new synchronization on the signing path in exchange for a liveness blip that already fails closed.
func (ns *nodeServer) handleRequest(pv types.PrivValidator, req privvalproto.Message, chainID string) (privvalproto.Message, error) {
	if ns.retired.Load() {
		return privval.DefaultValidationRequestHandler(pv, req, retiredChainID)
	}
	ns.touch()
	return privval.DefaultValidationRequestHandler(pv, req, chainID)
}

func (ns *nodeServer) silentFor() time.Duration {
	return time.Since(time.Unix(0, ns.lastActivity.Load()))
}

// retiredChainID is a sentinel passed to cometbft's request handler to make it refuse every
// request on a retired connection.
//
// Refusing this way, rather than returning a bare error, is deliberate: SignerServer replies with
// whatever message the handler returns, so a refusal must still be a well-formed response. The
// chain-ID mismatch path is the only one that produces a properly wrapped RemoteSignerError for
// *every* request type — notably PubKeyRequest, where a handler error yields an empty response
// message instead. Gating the PrivValidator itself would leave that case malformed.
//
// The value cannot collide with a real chain ID: chain IDs are non-empty and cannot contain spaces.
const retiredChainID = "\x00 cosmosigner retired connection"

// dial is the endpoint's SocketDialer. It returns a connection, or an error only once the connector
// is retired: cometbft's service loop exits for good on a dialer error, so returning one while still
// serving would leave the node without a signer until something recreated the connector. A
// connection is returned only while the connector is not retired, see handOver.
func (ns *nodeServer) dial(connKey crypto.PrivKey, timeoutReadWrite, retryWait time.Duration, logger cmtlog.Logger) (net.Conn, error) {
	for {
		conn, err := ns.dialOnce(connKey, timeoutReadWrite)
		if err == nil {
			return conn, nil
		}
		if ns.dialCtx.Err() != nil {
			return nil, errConnectorRetired
		}
		logger.Debug("dial node", "err", err)
		select {
		case <-ns.dialCtx.Done():
			return nil, errConnectorRetired
		case <-time.After(retryWait):
		}
	}
}

func (ns *nodeServer) dialOnce(connKey crypto.PrivKey, timeoutReadWrite time.Duration) (net.Conn, error) {
	proto, address := cmtnet.ProtocolAndAddress(ns.addr)
	dialer := net.Dialer{Timeout: dialTimeout}
	raw, err := dialer.DialContext(ns.dialCtx, proto, address)
	if err != nil {
		return nil, err
	}
	conn := &onceCloseConn{Conn: raw}
	if !ns.track(conn) {
		_ = conn.Close()
		return nil, errConnectorRetired
	}
	// The node accepts one signer at a time, so the handshake can sit in its accept queue; the
	// deadline keeps that wait bounded.
	if err := conn.SetDeadline(time.Now().Add(timeoutReadWrite)); err != nil {
		_ = conn.Close()
		return nil, err
	}
	secret, err := p2pconn.MakeSecretConnection(conn, connKey)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if !ns.handOver() {
		_ = conn.Close()
		return nil, errConnectorRetired
	}
	return secret, nil
}

// onceCloseConn makes Close idempotent. Retirement closes the socket itself, ahead of the endpoint
// that owns the connection, and the endpoint reports a failed Close as an error.
type onceCloseConn struct {
	net.Conn
	once sync.Once
	err  error
}

func (c *onceCloseConn) Close() error {
	c.once.Do(func() { c.err = c.Conn.Close() })
	return c.err
}

// track records conn for closeConn, or reports false when the connector is already retired and the
// caller must close conn itself. Checking under connMu is what guarantees every socket is closed by
// exactly one side: closeConn runs after retired is set, so it either sees conn or track refuses it.
func (ns *nodeServer) track(conn net.Conn) bool {
	ns.connMu.Lock()
	defer ns.connMu.Unlock()
	if ns.retired.Load() {
		return false
	}
	ns.conn = conn
	return true
}

// handOver reports whether a connection whose handshake has completed may be given to the endpoint.
// The handshake does not observe dialCtx, so it can complete after retirement; the endpoint would
// install that connection and answer the node's pending request with a refusal. Checking under
// connMu orders this against closeConn: a connection handed over is one closeConn has yet to close.
func (ns *nodeServer) handOver() bool {
	ns.connMu.Lock()
	defer ns.connMu.Unlock()
	return !ns.retired.Load()
}

// closeConn closes the last dialed socket, whatever stage it reached: mid-handshake, returned by
// dial but not yet installed in the endpoint, or serving. The endpoint's own Close only covers the
// last of these.
func (ns *nodeServer) closeConn() {
	ns.connMu.Lock()
	defer ns.connMu.Unlock()
	if ns.conn != nil {
		_ = ns.conn.Close()
	}
}

// retireReason classifies why a connection should be recreated, or retireNone to keep it.
type retireReason int

const (
	retireNone retireReason = iota
	retireSilent
)

// observe updates the connection-state latch and reports whether this connection should be
// retired. It is the single classifier shared by the reconcile pass and the between-tick health
// scan, so both agree on when a connection is dead — a scan with its own copy of these rules
// silently disagreed with reconcile about the latch and never fired.
//
// Callers must hold Lifecycle.mu.
func (ns *nodeServer) observe(staleTimeout time.Duration) retireReason {
	if ns.ep.IsConnected() {
		// Start the silence clock at connection establishment, not at connector creation — a
		// connector that spent time dialing a not-yet-up node must not be judged "silent" the
		// instant it connects (that would kill the handshake before the first request).
		if !ns.connected {
			ns.connected = true
			ns.touch()
			return retireNone
		}
		// Live socket gone silent → dead peer / EOF-spin.
		if ns.silentFor() > staleTimeout {
			return retireSilent
		}
		return retireNone
	}
	// Still dialing: the connector keeps trying until it is retired, so there is nothing to recycle.
	ns.connected = false
	return retireNone
}

// Lifecycle serves the gated PrivValidator to a dynamic set of target nodes,
// but only while this process holds raft leadership. On every reconcile it
// resolves the NodeSource and diffs it against the live connections: new nodes
// get a connector, removed nodes are dropped, and dead connections are
// recreated. On leadership loss it tears down everything; a non-leader never
// serves signatures. Graceful shutdown hands off leadership before retiring
// connections, so a node loses this signer only once another replica can dial
// it.
type Lifecycle struct {
	cfg     Config
	nodes   NodeSource
	pv      types.PrivValidator
	connKey crypto.PrivKey
	store   state.StateStore
	logger  cmtlog.Logger

	mu      sync.Mutex
	servers map[string]*nodeServer // keyed by node address

	// wake requests an immediate reconcile instead of waiting out the tick. Buffered with size 1:
	// a pending wake already covers any further request, so signalling never blocks.
	wake chan struct{}
	// stopping tracks in-flight asynchronous connection teardowns so shutdown can wait for them.
	stopping sync.WaitGroup
	// discoveryPendingUntil keeps discovery on the fast cadence for a bounded window after a
	// connection is retired, even once nothing in the serving set looks unhealthy. Guarded by mu.
	discoveryPendingUntil time.Time

	// status is the serving set as of the last reconcile pass or health scan, published for Status.
	status atomic.Pointer[[]servedNode]
}

// servedNode is one entry of the published serving set.
type servedNode struct {
	addr      string
	connected bool
	ns        *nodeServer
}

// NodeStatus describes one node connection held by this replica.
type NodeStatus struct {
	Address string
	// Connected is as of the last reconcile pass or health scan.
	Connected bool
	// LastActivity is the last request handled on the connection (pings included); zero while not
	// connected.
	LastActivity time.Time
}

// Status returns the nodes this replica is serving, sorted by address; empty on a non-leader.
//
// It reads a snapshot instead of the live connections: asking an endpoint whether it is connected
// waits on the lock its service loop holds for a whole read, up to TimeoutReadWrite, and l.mu is
// held across that same call during a reconcile. A status request must not queue behind either.
func (l *Lifecycle) Status() []NodeStatus {
	served := l.status.Load()
	if served == nil {
		return nil
	}
	nodes := make([]NodeStatus, 0, len(*served))
	for _, n := range *served {
		node := NodeStatus{Address: n.addr, Connected: n.connected}
		if n.connected {
			node.LastActivity = time.Unix(0, n.ns.lastActivity.Load())
		}
		nodes = append(nodes, node)
	}
	return nodes
}

// publishStatus snapshots the serving set for Status. Callers must hold l.mu.
func (l *Lifecycle) publishStatus() {
	served := make([]servedNode, 0, len(l.servers))
	for addr, ns := range l.servers {
		served = append(served, servedNode{addr: addr, connected: ns.connected, ns: ns})
	}
	sort.Slice(served, func(i, j int) bool { return served[i].addr < served[j].addr })
	l.status.Store(&served)
}

// retire stops a node connection and drops it from the serving set.
//
// The map entry is deleted synchronously — that is what makes the connection unreachable — while
// srv.Stop() runs in the background. Stop() blocks until the service loop leaves its in-flight
// ReadMessage, up to TimeoutReadWrite (3s by default) per connection, and it is called with l.mu
// held; doing it inline stalls discovery for every other node behind a socket that is already dead.
// That is the compounding cost behind a rendezvous that takes minutes: each reconcile pass pays the
// teardown of every dead peer before it can redial any of them.
//
// Deleting the map entry is NOT what stops the connection serving: SignerServer's service loop
// never consults the map, so until Stop() lands the endpoint would still answer signing requests.
// The retired flag closes that gap synchronously — the request handler refuses every request once
// it is set, so a removed node cannot race its replacement to reserve a height/round/step while the
// asynchronous Stop() is still in flight.
//
// A refusal must not reach the node, though. The node holds one signer connection and takes a
// refusal as that signer's answer: one that has just started listening gives up on a refused
// public-key request instead of accepting the next signer's dial. So the socket is closed here as
// well, before Stop(), which can spend its whole wait behind a read that would otherwise deliver
// the node's request to the refusing handler. Closing does not block. It costs a request that was
// already being handled its reply — see handleRequest for why that is safe.
//
// Stop() does not reach a connector that is still dialing either, so retirement also cancels the
// dial, and the same close aborts a handshake in flight: a retired connector that kept dialing
// could win the node's single signer slot and then refuse every request on it.
func (l *Lifecycle) retire(addr string, ns *nodeServer) {
	// Synchronous: disables signing on this connection before the caller releases l.mu.
	ns.retired.Store(true)
	ns.stopDial()
	ns.closeConn()
	delete(l.servers, addr)
	// A retired address usually means a pod is being replaced and the replacement's DNS record is not
	// published yet. In a multi-node target set the dead address is simply dropped, so once this entry
	// is gone nothing looks unhealthy and liveness alone would stop driving discovery — leaving the
	// replacement to the periodic tick. Keep discovery fast for a bounded window instead.
	l.discoveryPendingUntil = time.Now().Add(l.discoveryPendingWindow())
	l.stopping.Add(1)
	go func() {
		defer l.stopping.Done()
		_ = ns.srv.Stop()
		// A retired connection usually means the node is being replaced (new pod, new IP), so the
		// resolved node set is likely stale too. Re-resolve now rather than waiting out the tick.
		l.requestReconcile()
	}()
}

// requestReconcile asks the run loop to reconcile before its next tick. It never blocks.
func (l *Lifecycle) requestReconcile() {
	select {
	case l.wake <- struct{}{}:
	default:
	}
}

// discoveryPendingWindow is how long discovery stays fast after a retirement, giving a replacement
// pod's DNS record time to appear. Bounded so a permanently-removed node settles back to the normal
// interval rather than polling forever.
func (l *Lifecycle) discoveryPendingWindow() time.Duration {
	if l.cfg.ReconcileInterval > 30*time.Second {
		return 30 * time.Second
	}
	return l.cfg.ReconcileInterval
}

// watchInterval is how often connection health is sampled between reconciles. Detecting a dead
// connection is cheap; acting on it is not, so the scan only ever signals the run loop.
func (l *Lifecycle) watchInterval() time.Duration {
	// Sample well inside StaleConnTimeout so a dead socket is noticed promptly after it goes stale,
	// but never faster than 250ms.
	d := l.cfg.StaleConnTimeout / 4
	if d < 250*time.Millisecond {
		d = 250 * time.Millisecond
	}
	if d > l.cfg.ReconcileInterval {
		d = l.cfg.ReconcileInterval
	}
	return d
}

// needsFastDiscovery reports whether discovery should keep running at the watch cadence instead of
// falling back to ReconcileInterval. True when any connection is eligible for retirement, while any
// connector is merely unconnected, and for a bounded window after any retirement.
//
// The unconnected case matters because DNS lags pod churn: when a node is replaced, the first wake
// after teardown often still resolves the dead address, so reconcile recreates a connector for it.
// That connector dials the dead address indefinitely and is never retired on its own, so keying re-
// resolution on retirement alone would go quiet exactly when the replacement record is about to
// appear — leaving the tick to find it, which is the delay this is meant to remove. Staying fast
// while anything is unconnected keeps re-resolving until the replacement is actually being served.
//
// observe() latches connection state, so this is not read-only; reconcile remains the only mutator
// of the servers map itself.
func (l *Lifecycle) needsFastDiscovery() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	// The scan can be the first to see a connection come up, and then asks for no reconcile.
	defer l.publishStatus()
	if time.Now().Before(l.discoveryPendingUntil) {
		return true
	}
	for _, ns := range l.servers {
		if ns.observe(l.cfg.StaleConnTimeout) != retireNone {
			return true
		}
		if !ns.connected {
			return true
		}
	}
	return false
}

func New(cfg Config, nodes NodeSource, pv types.PrivValidator, connKey crypto.PrivKey, store state.StateStore, logger cmtlog.Logger) *Lifecycle {
	if cfg.TimeoutReadWrite <= 0 {
		cfg.TimeoutReadWrite = 3 * time.Second
	}
	if cfg.RetryWait <= 0 {
		cfg.RetryWait = 100 * time.Millisecond
	}
	if cfg.ReconcileInterval <= 0 {
		cfg.ReconcileInterval = 5 * time.Second
	}
	if cfg.StaleConnTimeout <= 0 {
		cfg.StaleConnTimeout = 15 * time.Second
	}
	return &Lifecycle{
		cfg:     cfg,
		nodes:   nodes,
		pv:      pv,
		connKey: connKey,
		store:   store,
		logger:  logger,
		servers: make(map[string]*nodeServer),
		wake:    make(chan struct{}, 1),
	}
}

// Run reconciles serving state with raft leadership and the resolved node set
// until ctx is cancelled. The periodic tick backstops a missed LeaderCh
// transition, refreshes node discovery, and recovers dead connections.
// Retiring a connection also wakes the loop directly, so a node replaced by a
// new pod (and so a new IP) is rediscovered without waiting out the tick. On cancellation,
// a bounded leadership handoff runs first and the connections are torn down after it.
func (l *Lifecycle) Run(ctx context.Context) error {
	ticker := time.NewTicker(l.cfg.ReconcileInterval)
	defer ticker.Stop()
	watch := time.NewTicker(l.watchInterval())
	defer watch.Stop()

	l.reconcile()
	for {
		select {
		case <-ctx.Done():
			l.transferLeadership()
			l.stopAll()
			l.stopping.Wait()
			return ctx.Err()
		case <-l.store.LeaderCh():
			l.reconcile()
		case <-l.wake:
			l.reconcile()
		case <-watch.C:
			// Cheap health scan between ticks: a dead or still-unconnected connection means a node is
			// likely being replaced at a new address, so keep re-resolving at this cadence until the
			// replacement is actually served instead of waiting out the interval.
			if l.needsFastDiscovery() {
				l.reconcile()
			}
		case <-ticker.C:
			l.reconcile()
		}
	}
}

func (l *Lifecycle) reconcile() {
	if !l.store.IsLeader() {
		l.stopAll()
		return
	}

	desired, err := l.nodes.Nodes()
	if err != nil {
		// Keep existing connections; a transient resolve failure must not drop
		// a working signer.
		l.logger.Error("resolve target nodes", "source", l.nodes.Describe(), "err", err)
		return
	}
	want := make(map[string]struct{}, len(desired))
	for _, addr := range desired {
		want[addr] = struct{}{}
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	defer l.publishStatus()

	for addr, ns := range l.servers {
		if _, wanted := want[addr]; !wanted {
			l.retire(addr, ns)
			l.logger.Info("stopped serving node", "node", addr)
			continue
		}
		if ns.observe(l.cfg.StaleConnTimeout) == retireSilent {
			silent := ns.silentFor().Round(time.Second)
			l.retire(addr, ns)
			l.logger.Info("recycling silent signer connection", "node", addr, "silent", silent)
		}
	}
	for addr := range want {
		if _, ok := l.servers[addr]; ok {
			continue
		}
		ns, err := l.startOne(addr)
		if err != nil {
			l.logger.Error("start signer server", "node", addr, "err", err)
			continue
		}
		l.servers[addr] = ns
		l.logger.Info("serving remote signer", "node", addr)
	}
}

func (l *Lifecycle) startOne(addr string) (*nodeServer, error) {
	ns := l.newNodeServer(addr)
	if err := ns.srv.Start(); err != nil {
		ns.stopDial()
		return nil, err
	}
	return ns, nil
}

// newNodeServer builds the connector for addr without starting it.
func (l *Lifecycle) newNodeServer(addr string) *nodeServer {
	ns := &nodeServer{addr: addr}
	ns.dialCtx, ns.stopDial = context.WithCancel(context.Background())
	logger := l.logger.With("node", addr)
	ns.ep = privval.NewSignerDialerEndpoint(
		logger,
		func() (net.Conn, error) {
			return ns.dial(l.connKey, l.cfg.TimeoutReadWrite, l.cfg.RetryWait, logger)
		},
		privval.SignerDialerEndpointTimeoutReadWrite(l.cfg.TimeoutReadWrite),
		// ns.dial retries by itself and fails only once retired, so the endpoint's own loop gets a
		// single attempt and no wait: on that error the service loop ends, which is what stops a
		// retired connector from dialing.
		privval.SignerDialerEndpointConnRetries(1),
		privval.SignerDialerEndpointRetryWaitInterval(0),
	)
	ns.srv = privval.NewSignerServer(ns.ep, l.cfg.ChainID, l.pv)
	ns.touch()
	ns.srv.SetRequestHandler(ns.handleRequest)
	return ns
}

func (l *Lifecycle) stopAll() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for addr, ns := range l.servers {
		l.retire(addr, ns)
	}
	l.publishStatus()
}

func (l *Lifecycle) transferLeadership() {
	transferer, ok := l.store.(state.LeadershipTransferer)
	if !ok || !l.store.IsLeader() {
		return
	}
	// Run's context is cancelled; the store bounds this shutdown operation itself.
	if err := transferer.TransferLeadership(context.Background()); err != nil {
		l.logger.Error("raft leadership handoff failed; followers will elect after the heartbeat timeout", "err", err)
	} else if !l.store.IsLeader() {
		l.logger.Info("no longer raft leader; continuing shutdown")
	}
}
