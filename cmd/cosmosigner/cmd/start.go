package cmd

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	cmtlog "github.com/cometbft/cometbft/libs/log"
	"github.com/hashicorp/go-hclog"
	"github.com/spf13/cobra"

	"github.com/voluzi/cosmosigner/internal/backend"
	"github.com/voluzi/cosmosigner/internal/config"
	"github.com/voluzi/cosmosigner/internal/server"
	"github.com/voluzi/cosmosigner/internal/signer"
	"github.com/voluzi/cosmosigner/internal/state"
)

// NewStartCmd builds the `start` command.
func NewStartCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "start",
		Short: "Run the remote signer",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfgFile, _ := cmd.Flags().GetString("config")
			if cfgFile == "" {
				cfgFile = os.Getenv("COSMOSIGNER_CONFIG")
			}
			cfg, err := config.Load(cfgFile, func(c *config.Config) error { return overlayStartFlags(cmd, c) })
			if err != nil {
				return err
			}
			return runStart(*cfg)
		},
	}

	d := config.Defaults()
	f := cmd.Flags()
	f.String("chain-id", "", "chain id")
	f.String("expected-public-key", "", "expected consensus public key (base64); refuse startup on mismatch")
	f.StringSlice("node", nil, "node privval address (repeatable)")
	f.String("node-service", "", "headless service host:port to auto-discover nodes from (mutually exclusive with --node)")
	f.String("conn-key", d.ConnKey, "path to the SecretConnection identity key")
	f.String("state-dir", d.StateDir, "state directory")
	f.Duration("reconcile-interval", d.ReconcileInterval, "how often to re-resolve nodes / re-check leadership")
	f.Duration("stale-conn-timeout", d.StaleConnTimeout, "recycle a node connection with no inbound activity for this long")
	f.String("raft-node-id", d.Raft.NodeID, "raft node id")
	f.String("raft-bind", d.Raft.BindAddr, "raft transport bind address")
	f.String("raft-advertise", "", "raft advertise address (defaults to bind)")
	f.String("raft-data-dir", d.Raft.DataDir, "raft data directory")
	f.Bool("raft-bootstrap", false, "seed a new raft cluster from --raft-member (set on one node, or all nodes identically)")
	f.StringArray("raft-member", nil, "raft member as id=address — the full set INCLUDING self, identical on every node (repeatable)")
	f.String("raft-tls-cert", "", "raft mTLS certificate (PEM); enables mutual TLS on the raft transport when set with --raft-tls-key and --raft-tls-ca")
	f.String("raft-tls-key", "", "raft mTLS private key (PEM)")
	f.String("raft-tls-ca", "", "raft mTLS CA bundle (PEM) used to verify peer certificates")
	registerBackendFlags(cmd)
	return cmd
}

// overlayStartFlags applies explicitly-set flags onto the loaded config.
func overlayStartFlags(cmd *cobra.Command, c *config.Config) error {
	f := cmd.Flags()
	s := func(name string, dst *string) {
		if f.Changed(name) {
			*dst, _ = f.GetString(name)
		}
	}
	s("chain-id", &c.ChainID)
	s("expected-public-key", &c.ExpectedPublicKey)
	if f.Changed("node") {
		c.NodeAddrs, _ = f.GetStringSlice("node")
	}
	s("node-service", &c.NodeService)
	s("conn-key", &c.ConnKey)
	s("state-dir", &c.StateDir)
	if f.Changed("reconcile-interval") {
		c.ReconcileInterval, _ = f.GetDuration("reconcile-interval")
	}
	if f.Changed("stale-conn-timeout") {
		c.StaleConnTimeout, _ = f.GetDuration("stale-conn-timeout")
	}
	if f.Changed("log-level") {
		c.LogLevel, _ = f.GetString("log-level")
	}
	s("raft-node-id", &c.Raft.NodeID)
	s("raft-bind", &c.Raft.BindAddr)
	s("raft-advertise", &c.Raft.Advertise)
	s("raft-data-dir", &c.Raft.DataDir)
	if f.Changed("raft-bootstrap") {
		c.Raft.Bootstrap, _ = f.GetBool("raft-bootstrap")
	}
	if f.Changed("raft-member") {
		raw, _ := f.GetStringArray("raft-member")
		members, err := parseMembers(raw)
		if err != nil {
			return err
		}
		c.Raft.Members = members
	}
	s("raft-tls-cert", &c.Raft.TLSCert)
	s("raft-tls-key", &c.Raft.TLSKey)
	s("raft-tls-ca", &c.Raft.TLSCA)
	overlayBackendFlags(cmd, &c.Backend)
	return nil
}

func parseMembers(raw []string) ([]config.Member, error) {
	members := make([]config.Member, 0, len(raw))
	for _, m := range raw {
		m = strings.TrimSpace(m)
		id, addr, ok := strings.Cut(m, "=")
		id, addr = strings.TrimSpace(id), strings.TrimSpace(addr)
		if !ok || id == "" || addr == "" {
			return nil, fmt.Errorf("invalid --raft-member %q: want id=address", m)
		}
		members = append(members, config.Member{ID: id, Address: addr})
	}
	return members, nil
}

func runStart(cfg config.Config) error {
	logger := newCmtLogger(cfg.LogLevel)
	raftLogger := hclog.New(&hclog.LoggerOptions{
		Name:   "raft",
		Level:  hclog.LevelFromString(cfg.LogLevel),
		Output: os.Stderr,
	})

	be, err := backend.New(cfg.Backend)
	if err != nil {
		return err
	}
	defer be.Close()
	if err := verifyExpectedPublicKey(be, cfg.ExpectedPublicKey); err != nil {
		return err
	}

	// Fail fast if the backend can't actually sign (e.g. a Vault token missing
	// the sign capability, or one that will expire and can't be renewed) rather
	// than discovering it at the first vote.
	if pf, ok := be.(interface{ VerifyCanSign() error }); ok {
		if err := pf.VerifyCanSign(); err != nil {
			return fmt.Errorf("backend preflight: %w", err)
		}
		logger.Info("backend preflight ok", "backend", cfg.Backend.Type)
	}

	raftCfg := state.RaftConfig{
		NodeID:    cfg.Raft.NodeID,
		BindAddr:  cfg.Raft.BindAddr,
		Advertise: cfg.Raft.Advertise,
		DataDir:   cfg.Raft.DataDir,
		Bootstrap: cfg.Raft.Bootstrap,
		TLS: state.TLSConfig{
			CertFile: cfg.Raft.TLSCert,
			KeyFile:  cfg.Raft.TLSKey,
			CAFile:   cfg.Raft.TLSCA,
		},
	}
	for _, m := range cfg.Raft.Members {
		raftCfg.Members = append(raftCfg.Members, state.Member{ID: m.ID, Address: m.Address})
	}
	store, err := state.NewRaftStore(raftCfg, raftLogger)
	if err != nil {
		return err
	}
	defer store.Close()

	pv, err := signer.New(be, store)
	if err != nil {
		return err
	}

	connKey, err := server.LoadOrGenConnKey(cfg.ConnKey)
	if err != nil {
		return err
	}

	nodes, err := buildNodeSource(cfg)
	if err != nil {
		return err
	}

	lc := server.New(server.Config{
		ChainID:           cfg.ChainID,
		TimeoutReadWrite:  cfg.TimeoutReadWrite,
		MaxRetries:        cfg.MaxRetries,
		RetryWait:         cfg.RetryWait,
		ReconcileInterval: cfg.ReconcileInterval,
		StaleConnTimeout:  cfg.StaleConnTimeout,
	}, nodes, pv, connKey, store, logger)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	logger.Info("cosmosigner starting",
		"chain_id", cfg.ChainID, "nodes", nodes.Describe(), "backend", cfg.Backend.Type,
		"raft_node", cfg.Raft.NodeID, "raft_mtls", raftCfg.TLS.Enabled())

	if err := lc.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	logger.Info("cosmosigner stopped")
	return nil
}

func verifyExpectedPublicKey(be backend.KeyBackend, expected string) error {
	if expected == "" {
		return nil
	}
	want, err := base64.StdEncoding.DecodeString(expected)
	if err != nil {
		return fmt.Errorf("decode expected public key: %w", err)
	}
	pub, err := be.PubKey()
	if err != nil {
		return fmt.Errorf("get backend public key: %w", err)
	}
	if !bytes.Equal(pub.Bytes(), want) {
		return fmt.Errorf("backend public key does not match expected public key")
	}
	return nil
}

func buildNodeSource(cfg config.Config) (server.NodeSource, error) {
	if cfg.NodeService != "" {
		return server.NewHeadlessServiceNodes(cfg.NodeService)
	}
	return server.StaticNodes(cfg.NodeAddrs), nil
}

func newCmtLogger(level string) cmtlog.Logger {
	logger := cmtlog.NewTMLogger(cmtlog.NewSyncWriter(os.Stdout))
	switch level {
	case "debug":
		return cmtlog.NewFilter(logger, cmtlog.AllowDebug())
	case "warn", "error":
		return cmtlog.NewFilter(logger, cmtlog.AllowError())
	default:
		return cmtlog.NewFilter(logger, cmtlog.AllowInfo())
	}
}
