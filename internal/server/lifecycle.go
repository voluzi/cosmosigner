package server

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cometbft/cometbft/crypto"
	cmtlog "github.com/cometbft/cometbft/libs/log"
	"github.com/cometbft/cometbft/privval"
	privvalproto "github.com/cometbft/cometbft/proto/tendermint/privval"
	"github.com/cometbft/cometbft/types"

	"github.com/voluzi/cosmosigner/internal/state"
)

// Config configures the privval connection lifecycle.
type Config struct {
	ChainID          string
	TimeoutReadWrite time.Duration
	// MaxRetries × RetryWait is the dial budget for a single connector: how long
	// it keeps trying to reach a node before the connector is recreated. It is
	// deliberately long so a (re)starting node always finds cosmosigner dialing.
	MaxRetries        int
	RetryWait         time.Duration
	ReconcileInterval time.Duration // how often to re-resolve nodes / re-check leadership
	// StaleConnTimeout recycles a node connection with no inbound activity for
	// this long. A healthy node pings every ~3s, so silence on a *connected*
	// socket means the link is dead in a way cometbft's endpoint cannot recover
	// from by itself (see nodeServer). Must comfortably exceed the ping interval.
	StaleConnTimeout time.Duration
}

// nodeServer is one node's signer connection with activity/creation timestamps.
//
// Two recovery mechanisms are needed on top of cometbft's SignerServer:
//
//   - Dead-but-"connected" socket: cometbft's signerEndpoint only drops its
//     connection on read/write TIMEOUTS. If the node closes the TCP connection
//     (restart/crash), reads return EOF, the endpoint still reports IsConnected,
//     and the service loop spins on EOF without re-dialing. Detected as a
//     *connected* socket that has gone silent past StaleConnTimeout.
//   - Exhausted connector: the service loop exits once the dialer's retry budget
//     is exhausted (node down longer than MaxRetries×RetryWait). Detected as a
//     *disconnected* server older than the dial budget.
//
// Either triggers a recreate on the reconcile tick.
type nodeServer struct {
	srv          *privval.SignerServer
	ep           *privval.SignerDialerEndpoint
	createdAt    time.Time
	connected    bool         // last observed connection state (reconcile-only)
	lastActivity atomic.Int64 // unix nanos of the last handled request (pings included)
	// retired marks this connection as no longer serving. It is set synchronously when the
	// connection is dropped from the serving set, before the (blocking) Stop() runs — see retire.
	retired atomic.Bool
}

func (ns *nodeServer) touch() { ns.lastActivity.Store(time.Now().UnixNano()) }

// handleRequest serves one privval request, recording inbound activity (pings included) for
// dead-socket detection.
//
// A retired connection must not serve, even before its asynchronous Stop() has landed: the
// SignerServer service loop does not consult the serving set, so this check is what makes
// retirement take effect immediately. Without it, a node removed from the target set could keep
// signing until Stop() completed — long enough to race its replacement for a height/round/step
// reservation.
//
// The check is not a drain: a request that has already passed it runs to completion (bounded by the
// backend signing call) even as the replacement connection starts, because SignerServer.Stop() does
// not wait for in-flight handlers. That residual overlap is safe rather than merely unlikely — both
// connections share one GatedPrivValidator, so both reserve through raft, and fsm.applyReserve is
// total over the H/R/S comparison: identical signBytes reuse the cached signature (or re-sign
// deterministically), a timestamp-only difference signs the *reserved* bytes, and anything else at
// the same H/R/S is refused with ErrConflict. Ordering is decided by the raft log, not by goroutine
// scheduling. So the overlap can cost one refused-and-retried request, never a second distinct
// signature at one H/R/S. Draining would mean blocking replacement creation on an in-flight count —
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

// retireReason classifies why a connection should be recreated, or retireNone to keep it.
type retireReason int

const (
	retireNone retireReason = iota
	retireSilent
	retireExhausted
)

// observe updates the connection-state latch and reports whether this connection should be
// retired. It is the single classifier shared by the reconcile pass and the between-tick health
// scan, so both agree on when a connection is dead — a scan with its own copy of these rules
// silently disagreed with reconcile about the latch and never fired.
//
// Callers must hold Lifecycle.mu.
func (ns *nodeServer) observe(staleTimeout, dialBudget time.Duration) retireReason {
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
	ns.connected = false
	// Not connected and past the dial budget → connector exhausted.
	if time.Since(ns.createdAt) > dialBudget {
		return retireExhausted
	}
	return retireNone
}

// Lifecycle serves the gated PrivValidator to a dynamic set of target nodes,
// but only while this process holds raft leadership. On every reconcile it
// resolves the NodeSource and diffs it against the live connections: new nodes
// get a connector, removed nodes are dropped, and dead/exhausted connectors are
// recreated. On leadership loss it tears down everything; a non-leader never
// serves signatures.
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
func (l *Lifecycle) retire(addr string, ns *nodeServer) {
	// Synchronous: disables signing on this connection before the caller releases l.mu.
	ns.retired.Store(true)
	delete(l.servers, addr)
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

// dialBudget is how long a connector may keep dialing before it is recreated: the endpoint's own
// retry budget plus one reconcile interval of slack, so a connector is never judged exhausted by
// the same pass that would have let it finish its last retry.
func (l *Lifecycle) dialBudget() time.Duration {
	return time.Duration(l.cfg.MaxRetries)*l.cfg.RetryWait + l.cfg.ReconcileInterval
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

// hasDeadConnection reports whether any served connection is eligible for retirement, using the
// same classifier as the reconcile pass so the two cannot disagree.
//
// This exists because a node pod that dies is usually replaced at a NEW address, so the resolved
// target set is stale from the moment the pod dies. Waiting a full ReconcileInterval to notice
// couples rendezvous latency to a tick that has no relationship to how fast pods churn — which is
// what makes a healthy restart look like a multi-minute outage.
//
// observe() latches connection state, so this is not read-only; reconcile remains the only mutator
// of the servers map itself.
func (l *Lifecycle) hasDeadConnection() bool {
	dialBudget := l.dialBudget()

	l.mu.Lock()
	defer l.mu.Unlock()
	for _, ns := range l.servers {
		if ns.observe(l.cfg.StaleConnTimeout, dialBudget) != retireNone {
			return true
		}
	}
	return false
}

func New(cfg Config, nodes NodeSource, pv types.PrivValidator, connKey crypto.PrivKey, store state.StateStore, logger cmtlog.Logger) *Lifecycle {
	if cfg.TimeoutReadWrite <= 0 {
		cfg.TimeoutReadWrite = 3 * time.Second
	}
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = 6000 // ~10min of continuous dialing at the default RetryWait
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
// transition, refreshes node discovery, and recovers dead/exhausted connectors.
// Retiring a connection also wakes the loop directly, so a node replaced by a
// new pod (and so a new IP) is rediscovered without waiting out the tick.
func (l *Lifecycle) Run(ctx context.Context) error {
	ticker := time.NewTicker(l.cfg.ReconcileInterval)
	defer ticker.Stop()
	watch := time.NewTicker(l.watchInterval())
	defer watch.Stop()

	l.reconcile()
	for {
		select {
		case <-ctx.Done():
			l.stopAll()
			l.stopping.Wait()
			return ctx.Err()
		case <-l.store.LeaderCh():
			l.reconcile()
		case <-l.wake:
			l.reconcile()
		case <-watch.C:
			// Cheap health scan between ticks: a dead connection means the node is likely being
			// replaced at a new address, so reconcile now instead of waiting out the interval.
			if l.hasDeadConnection() {
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

	dialBudget := l.dialBudget()

	l.mu.Lock()
	defer l.mu.Unlock()

	for addr, ns := range l.servers {
		if _, wanted := want[addr]; !wanted {
			l.retire(addr, ns)
			l.logger.Info("stopped serving node", "node", addr)
			continue
		}
		switch ns.observe(l.cfg.StaleConnTimeout, dialBudget) {
		case retireSilent:
			silent := ns.silentFor().Round(time.Second)
			l.retire(addr, ns)
			l.logger.Info("recycling silent signer connection", "node", addr, "silent", silent)
		case retireExhausted:
			l.retire(addr, ns)
			l.logger.Info("redialing exhausted connector", "node", addr)
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
	dialer := privval.DialTCPFn(addr, l.cfg.TimeoutReadWrite, l.connKey)
	ep := privval.NewSignerDialerEndpoint(
		l.logger.With("node", addr),
		dialer,
		privval.SignerDialerEndpointTimeoutReadWrite(l.cfg.TimeoutReadWrite),
		privval.SignerDialerEndpointConnRetries(l.cfg.MaxRetries),
		privval.SignerDialerEndpointRetryWaitInterval(l.cfg.RetryWait),
	)
	srv := privval.NewSignerServer(ep, l.cfg.ChainID, l.pv)
	ns := &nodeServer{srv: srv, ep: ep, createdAt: time.Now()}
	ns.touch()
	srv.SetRequestHandler(ns.handleRequest)
	if err := srv.Start(); err != nil {
		return nil, err
	}
	return ns, nil
}

func (l *Lifecycle) stopAll() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for addr, ns := range l.servers {
		l.retire(addr, ns)
	}
}
