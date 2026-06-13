package state

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/raft"
	raftboltdb "github.com/hashicorp/raft-boltdb/v2"
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

// NewRaftStore creates an embedded-raft StateStore.
func NewRaftStore(cfg RaftConfig, logger hclog.Logger) (StateStore, error) {
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

	bolt, err := raftboltdb.NewBoltStore(filepath.Join(cfg.DataDir, "raft.db"))
	if err != nil {
		return nil, fmt.Errorf("bolt store: %w", err)
	}

	snaps, err := raft.NewFileSnapshotStoreWithLogger(cfg.DataDir, 2, logger)
	if err != nil {
		return nil, fmt.Errorf("snapshot store: %w", err)
	}

	advertiseAddr, err := net.ResolveTCPAddr("tcp", cfg.Advertise)
	if err != nil {
		return nil, fmt.Errorf("resolve advertise address %q: %w", cfg.Advertise, err)
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
