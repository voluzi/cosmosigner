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
}

func (ns *nodeServer) touch() { ns.lastActivity.Store(time.Now().UnixNano()) }

func (ns *nodeServer) silentFor() time.Duration {
	return time.Since(time.Unix(0, ns.lastActivity.Load()))
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
	}
}

// Run reconciles serving state with raft leadership and the resolved node set
// until ctx is cancelled. The periodic tick backstops a missed LeaderCh
// transition, refreshes node discovery, and recovers dead/exhausted connectors.
func (l *Lifecycle) Run(ctx context.Context) error {
	ticker := time.NewTicker(l.cfg.ReconcileInterval)
	defer ticker.Stop()

	l.reconcile()
	for {
		select {
		case <-ctx.Done():
			l.stopAll()
			return ctx.Err()
		case <-l.store.LeaderCh():
			l.reconcile()
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

	dialBudget := time.Duration(l.cfg.MaxRetries) * l.cfg.RetryWait

	l.mu.Lock()
	defer l.mu.Unlock()

	for addr, ns := range l.servers {
		_, wanted := want[addr]
		switch {
		case !wanted:
			_ = ns.srv.Stop()
			delete(l.servers, addr)
			l.logger.Info("stopped serving node", "node", addr)
		case ns.ep.IsConnected():
			// Start the silence clock at connection establishment, not at
			// connector creation — a connector that spent time dialing a
			// not-yet-up node must not be judged "silent" the instant it
			// connects (that would kill the handshake before the first request).
			if !ns.connected {
				ns.connected = true
				ns.touch()
			}
			// Live socket gone silent → dead peer / EOF-spin.
			if ns.silentFor() > l.cfg.StaleConnTimeout {
				_ = ns.srv.Stop()
				delete(l.servers, addr)
				l.logger.Info("recycling silent signer connection", "node", addr, "silent", ns.silentFor().Round(time.Second))
			}
		default:
			ns.connected = false
			// Not connected and past the dial budget → connector exhausted.
			if time.Since(ns.createdAt) > dialBudget+l.cfg.ReconcileInterval {
				_ = ns.srv.Stop()
				delete(l.servers, addr)
				l.logger.Info("redialing exhausted connector", "node", addr)
			}
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
	// Wrap the default handler to record inbound activity (pings included) for
	// dead-socket detection.
	srv.SetRequestHandler(func(pv types.PrivValidator, req privvalproto.Message, chainID string) (privvalproto.Message, error) {
		ns.touch()
		return privval.DefaultValidationRequestHandler(pv, req, chainID)
	})
	if err := srv.Start(); err != nil {
		return nil, err
	}
	return ns, nil
}

func (l *Lifecycle) stopAll() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for addr, ns := range l.servers {
		_ = ns.srv.Stop()
		delete(l.servers, addr)
	}
}
