package state

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/raft"
	raftboltdb "github.com/hashicorp/raft-boltdb/v2"
	"go.etcd.io/bbolt"
)

// Member is a raft cluster member (id + advertise address) used to seed the
// initial configuration.
type Member struct {
	ID      string
	Address string
}

// RaftConfig configures the embedded raft node.
type RaftConfig struct {
	NodeID    string
	BindAddr  string // raft transport listen address, e.g. 0.0.0.0:7070
	Advertise string // address peers use to reach this node; defaults to BindAddr
	DataDir   string
	Bootstrap bool
	// Members is the full initial member set INCLUDING this node, identical on
	// every node. Empty means a single-node cluster of just this node. Only the
	// nodes that have Bootstrap set seed the configuration; for a fresh cluster,
	// either set Bootstrap on exactly one node (others join bare) or on all
	// nodes with this identical Members list.
	Members      []Member
	ApplyTimeout time.Duration
	// TLS, when fully set, secures the inter-replica transport with mutual TLS.
	// Empty (the default) means plain TCP — only safe on a trusted network.
	TLS TLSConfig
}

type raftStore struct {
	raft      *raft.Raft
	fsm       *fsm
	bolt      *raftboltdb.BoltStore
	transport *raft.NetworkTransport

	applyTimeout time.Duration
}

var (
	// advertiseResolveTimeout bounds how long startup waits for the advertise address to become
	// resolvable. It stays well inside a typical Kubernetes startup probe budget, so a genuinely
	// wrong address still fails the pod rather than hanging invisibly. Variables, not constants,
	// so tests can shrink the budget.
	advertiseResolveTimeout = 90 * time.Second
	// advertiseResolveInterval is how often resolution is retried within that budget.
	advertiseResolveInterval = time.Second
)

// boltOpenTimeout bounds the raft.db file-lock wait, so a database still held by a previous pod
// fails startup rather than blocking it indefinitely in a call that cannot observe cancellation.
const boltOpenTimeout = 30 * time.Second

// advertiseTypoHint is logged once a hostname has failed to resolve for this long, to name the
// likely cause. Hostname syntax is not a usable resolvability test — DNS labels may contain bytes
// that RFC 1123 forbids, and the resolver reports a typo and a not-yet-published record with the
// same "no such host" — so a persistent failure is surfaced rather than pre-rejected.
const advertiseTypoHint = 10 * time.Second

// resolveAdvertise resolves the address peers use to reach this node, retrying until
// advertiseResolveTimeout.
//
// Raft needs a concrete, advertisable *net.TCPAddr before the transport is built: the plain-TCP
// transport rejects a non-TCP or unspecified address, and NewRaft captures the local address once.
// So resolution cannot be deferred. But under a StatefulSet the per-pod headless DNS record is
// published moments after the pod starts, so a signer that resolves once and exits turns an
// ordinary startup race into a crashloop — one that resolves itself only via CrashLoopBackOff,
// after backoff has grown well past the DNS delay it was waiting on.
//
// Retrying here is safe: the resolved value only becomes visible to raft through the transport and
// BootstrapCluster, both strictly later, so a few seconds of waiting changes no bootstrap or
// membership assumption. Peer addresses are not resolved here at all — raft dials those lazily and
// retries on its own — so this waits on this node's own record only.
//
// Only the DNS lookup is retried. A structurally malformed address (missing or non-numeric port, no
// host) fails identically on every attempt, so retrying it would turn an operator typo into a
// 90-second hang instead of the immediate error it used to be. Hostname *spelling* is deliberately
// not pre-validated: a DNS label may legally contain bytes RFC 1123 forbids, and the resolver
// reports a typo and a not-yet-published record identically, so a syntax screen would reject names
// that do resolve. A persistent failure is surfaced with a hint instead. Each lookup is bound to the
// remaining budget, so a stalled resolver cannot hang past it either.
func resolveAdvertise(ctx context.Context, advertise string, logger hclog.Logger) (*net.TCPAddr, error) {
	host, portStr, err := net.SplitHostPort(advertise)
	if err != nil {
		return nil, fmt.Errorf("parse advertise address %q: %w", advertise, err)
	}
	port, err := net.DefaultResolver.LookupPort(ctx, "tcp", portStr)
	if err != nil {
		return nil, fmt.Errorf("parse advertise port of %q: %w", advertise, err)
	}
	if host == "" {
		return nil, fmt.Errorf("advertise address %q has no host; peers cannot reach an unspecified address", advertise)
	}
	ctx, cancel := context.WithTimeout(ctx, advertiseResolveTimeout)
	defer cancel()

	started := time.Now()
	for attempt := 1; ; attempt++ {
		// LookupIPAddr resolves an IP literal (zoned ones included) locally and instantly, so literals
		// return on the first pass without touching DNS. It is used rather than LookupIP because only
		// the IPAddr form carries the IPv6 zone a link-local advertise address needs to stay routable.
		// The context bounds each lookup by the remaining budget, so a stalled resolver cannot hang
		// past it.
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err == nil && len(ips) > 0 {
			addr := &net.TCPAddr{IP: ips[0].IP, Port: port, Zone: ips[0].Zone}
			if attempt > 1 {
				logger.Info("resolved advertise address", "advertise", advertise, "addr", addr.String(), "attempts", attempt)
			}
			return addr, nil
		}
		if err == nil {
			err = fmt.Errorf("no addresses for host %q", host)
		}
		if ctx.Err() != nil {
			return nil, fmt.Errorf("resolve advertise address %q after %s: %w", advertise, advertiseResolveTimeout, err)
		}
		warn := []any{"advertise", advertise, "attempt", attempt, "err", err}
		if time.Since(started) > advertiseTypoHint {
			// Past the point where a StatefulSet's own DNS record would normally have appeared, so
			// the likeliest remaining cause is a wrong address rather than a slow one.
			warn = append(warn, "hint", "check .raft.advertise for a typo; a per-pod record normally appears within seconds")
		}
		logger.Warn("advertise address not resolvable yet, retrying", warn...)

		select {
		case <-time.After(advertiseResolveInterval):
		case <-ctx.Done():
			return nil, fmt.Errorf("resolve advertise address %q after %s: %w", advertise, advertiseResolveTimeout, err)
		}
	}
}

// NewRaftStore creates an embedded-raft StateStore. Startup waits are bounded by their own budgets
// but are not externally cancellable; prefer NewRaftStoreContext from a signal-aware caller.
func NewRaftStore(cfg RaftConfig, logger hclog.Logger) (StateStore, error) {
	return NewRaftStoreContext(context.Background(), cfg, logger)
}

// NewRaftStoreContext creates an embedded-raft StateStore, using ctx for the startup waits that can
// block — currently advertise-address resolution, which retries while the per-pod DNS record is
// published. A terminating pod must exit on SIGTERM during that window rather than sit until its
// grace period expires.
func NewRaftStoreContext(ctx context.Context, cfg RaftConfig, logger hclog.Logger) (StateStore, error) {
	if cfg.ApplyTimeout <= 0 {
		cfg.ApplyTimeout = 10 * time.Second
	}
	if cfg.Advertise == "" {
		cfg.Advertise = cfg.BindAddr
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}

	rc := raft.DefaultConfig()
	rc.LocalID = raft.ServerID(cfg.NodeID)
	rc.Logger = logger

	f := newFSM()

	// Bound the file-lock wait. bbolt.Open blocks indefinitely by default when another process still
	// holds raft.db (an overlapping StatefulSet replacement), and it takes no context — so without a
	// timeout a SIGTERM during startup could not unblock it. Failing after boltOpenTimeout lets the
	// pod exit and be retried instead of hanging past its grace period.
	bolt, err := raftboltdb.New(raftboltdb.Options{
		Path:        filepath.Join(cfg.DataDir, "raft.db"),
		BoltOptions: &bbolt.Options{Timeout: boltOpenTimeout},
	})
	if err != nil {
		return nil, fmt.Errorf("bolt store: %w", err)
	}

	snaps, err := raft.NewFileSnapshotStoreWithLogger(cfg.DataDir, 2, logger)
	if err != nil {
		return nil, fmt.Errorf("snapshot store: %w", err)
	}

	advertiseAddr, err := resolveAdvertise(ctx, cfg.Advertise, logger)
	if err != nil {
		return nil, err
	}
	var transport *raft.NetworkTransport
	if cfg.TLS.Enabled() {
		sl, err := newTLSStreamLayer(cfg.BindAddr, advertiseAddr, cfg.TLS)
		if err != nil {
			return nil, err
		}
		transport = raft.NewNetworkTransportWithLogger(sl, 3, 10*time.Second, logger)
	} else {
		transport, err = raft.NewTCPTransportWithLogger(cfg.BindAddr, advertiseAddr, 3, 10*time.Second, logger)
		if err != nil {
			return nil, fmt.Errorf("tcp transport: %w", err)
		}
	}

	r, err := raft.NewRaft(rc, f, bolt, bolt, snaps, transport)
	if err != nil {
		return nil, fmt.Errorf("new raft: %w", err)
	}

	if cfg.Bootstrap {
		hasState, err := raft.HasExistingState(bolt, bolt, snaps)
		if err != nil {
			return nil, fmt.Errorf("check existing state: %w", err)
		}
		if !hasState {
			servers, err := bootstrapServers(cfg, rc.LocalID, transport.LocalAddr())
			if err != nil {
				return nil, err
			}
			if err := r.BootstrapCluster(raft.Configuration{Servers: servers}).Error(); err != nil {
				return nil, fmt.Errorf("bootstrap cluster: %w", err)
			}
		}
	}

	return &raftStore{
		raft:         r,
		fsm:          f,
		bolt:         bolt,
		transport:    transport,
		applyTimeout: cfg.ApplyTimeout,
	}, nil
}

// bootstrapServers builds the initial raft configuration. With no members it is
// a single-node cluster of self; otherwise the member list is used verbatim and
// MUST include this node (a common misconfiguration otherwise splits brains).
func bootstrapServers(cfg RaftConfig, localID raft.ServerID, localAddr raft.ServerAddress) ([]raft.Server, error) {
	if len(cfg.Members) == 0 {
		return []raft.Server{{ID: localID, Address: localAddr}}, nil
	}
	servers := make([]raft.Server, 0, len(cfg.Members))
	selfFound := false
	for _, m := range cfg.Members {
		if m.ID == "" || m.Address == "" {
			return nil, fmt.Errorf("raft member needs both id and address: %+v", m)
		}
		if raft.ServerID(m.ID) == localID {
			selfFound = true
		}
		servers = append(servers, raft.Server{
			ID:      raft.ServerID(m.ID),
			Address: raft.ServerAddress(m.Address),
		})
	}
	if !selfFound {
		return nil, fmt.Errorf("raft node-id %q is not in the member list %v", localID, cfg.Members)
	}
	return servers, nil
}

func (s *raftStore) Reserve(chainID string, height int64, round int32, step int8, signBytes []byte, ts time.Time) (ReserveResult, error) {
	if s.raft.State() != raft.Leader {
		return ReserveResult{}, ErrNotLeader
	}
	res, err := s.apply(command{
		Op:        opReserve,
		ChainID:   chainID,
		Height:    height,
		Round:     round,
		Step:      step,
		SignBytes: signBytes,
		Timestamp: ts,
	})
	if err != nil {
		return ReserveResult{}, err
	}
	return ReserveResult{
		Reuse:     res.reuse,
		SignBytes: res.signBytes,
		Signature: res.signature,
		Timestamp: res.timestamp,
	}, nil
}

func (s *raftStore) Commit(chainID string, height int64, round int32, step int8, signBytes, signature []byte) error {
	if s.raft.State() != raft.Leader {
		return ErrNotLeader
	}
	_, err := s.apply(command{
		Op:        opCommit,
		ChainID:   chainID,
		Height:    height,
		Round:     round,
		Step:      step,
		SignBytes: signBytes,
		Signature: signature,
	})
	return err
}

func (s *raftStore) apply(c command) (applyResult, error) {
	data, err := json.Marshal(c)
	if err != nil {
		return applyResult{}, fmt.Errorf("marshal command: %w", err)
	}
	future := s.raft.Apply(data, s.applyTimeout)
	if err := future.Error(); err != nil {
		// ErrNotLeader / ErrLeadershipLost / ErrEnqueueTimeout — fail closed.
		return applyResult{}, err
	}
	res, ok := future.Response().(applyResult)
	if !ok {
		return applyResult{}, fmt.Errorf("unexpected apply response type %T", future.Response())
	}
	if res.err != nil {
		return applyResult{}, res.err
	}
	return res, nil
}

func (s *raftStore) Get(chainID string) (*SignState, error) {
	st := s.fsm.get(chainID)
	if st == nil {
		return nil, ErrNoState
	}
	return st, nil
}

func (s *raftStore) IsLeader() bool { return s.raft.State() == raft.Leader }

func (s *raftStore) LeaderCh() <-chan bool { return s.raft.LeaderCh() }

func (s *raftStore) Close() error {
	if err := s.raft.Shutdown().Error(); err != nil {
		return fmt.Errorf("raft shutdown: %w", err)
	}
	if s.transport != nil {
		_ = s.transport.Close()
	}
	return s.bolt.Close()
}
