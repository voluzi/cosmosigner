// Package config defines the cosmosigner runtime configuration and a single
// Load entry point that layers, in increasing precedence: struct defaults
// (creasty/defaults), an optional YAML file, environment variables
// (caarlos0/env), and explicitly-set CLI flags (an overlay callback).
package config

import (
	"fmt"
	"time"

	"github.com/caarlos0/env/v11"
	"github.com/creasty/defaults"

	"github.com/voluzi/cosmosigner/internal/backend"
)

// Config is the full runtime configuration. Each field carries its YAML key,
// environment variable, and default in one place.
type Config struct {
	ChainID           string `yaml:"chain_id" env:"COSMOSIGNER_CHAIN_ID"`
	ExpectedPublicKey string `yaml:"expected_public_key" env:"COSMOSIGNER_EXPECTED_PUBLIC_KEY"`
	// NodeAddrs is a static list of node privval addresses (host:port).
	NodeAddrs []string `yaml:"nodes" env:"COSMOSIGNER_NODE" envSeparator:","`
	// NodeService is a Kubernetes headless service FQDN + port (host:port);
	// when set, target nodes are discovered from its DNS A-records. Mutually
	// exclusive with NodeAddrs.
	NodeService string `yaml:"node_service" env:"COSMOSIGNER_NODE_SERVICE"`
	ConnKey     string `yaml:"conn_key" env:"COSMOSIGNER_CONN_KEY" default:"./data/conn_key.json"`
	StateDir    string `yaml:"state_dir" env:"COSMOSIGNER_STATE_DIR" default:"./data"`
	LogLevel    string `yaml:"log_level" env:"COSMOSIGNER_LOG_LEVEL" default:"info"`

	// Connection tuning (durations are not YAML-friendly; flag/env/default only).
	ReconcileInterval time.Duration `yaml:"-" env:"COSMOSIGNER_RECONCILE_INTERVAL" default:"5s"`
	TimeoutReadWrite  time.Duration `yaml:"-" env:"COSMOSIGNER_CONN_TIMEOUT" default:"3s"`
	MaxRetries        int           `yaml:"-" env:"COSMOSIGNER_CONN_MAX_RETRIES" default:"6000"`
	RetryWait         time.Duration `yaml:"-" env:"COSMOSIGNER_CONN_RETRY_WAIT" default:"100ms"`
	// StaleConnTimeout recycles a node connection with no inbound activity for
	// this long; must comfortably exceed the node's ping interval (~3s).
	StaleConnTimeout time.Duration `yaml:"-" env:"COSMOSIGNER_STALE_CONN_TIMEOUT" default:"15s"`

	Backend backend.Config `yaml:"backend"`
	Raft    RaftConfig     `yaml:"raft"`
}

// RaftConfig configures the embedded raft node.
type RaftConfig struct {
	NodeID    string   `yaml:"node_id" env:"COSMOSIGNER_RAFT_NODE_ID" default:"node-1"`
	BindAddr  string   `yaml:"bind_addr" env:"COSMOSIGNER_RAFT_BIND" default:"127.0.0.1:7070"`
	Advertise string   `yaml:"advertise" env:"COSMOSIGNER_RAFT_ADVERTISE"`
	DataDir   string   `yaml:"data_dir" env:"COSMOSIGNER_RAFT_DATA_DIR" default:"./data/raft"`
	Bootstrap bool     `yaml:"bootstrap" env:"COSMOSIGNER_RAFT_BOOTSTRAP"`
	Members   []Member `yaml:"members"`
	// Optional mutual TLS for the inter-replica raft transport. All three must
	// be set together to enable it; empty (the default) means plain TCP, which
	// is only safe on a trusted/isolated network.
	TLSCert string `yaml:"tls_cert" env:"COSMOSIGNER_RAFT_TLS_CERT"`
	TLSKey  string `yaml:"tls_key" env:"COSMOSIGNER_RAFT_TLS_KEY"`
	TLSCA   string `yaml:"tls_ca" env:"COSMOSIGNER_RAFT_TLS_CA"`
}

// Member is a raft cluster member (id=address) — the full set including self,
// identical on every node.
type Member struct {
	ID      string `yaml:"id"`
	Address string `yaml:"address"`
}

// Defaults returns a Config populated only with struct defaults — useful for
// sourcing CLI flag defaults so --help shows real values.
func Defaults() Config {
	var c Config
	_ = defaults.Set(&c)
	return c
}

// Load builds the configuration: defaults → YAML file (if path set) → env →
// flag overlay (highest precedence), then validates.
func Load(path string, overlay func(*Config) error) (*Config, error) {
	var c Config
	if err := defaults.Set(&c); err != nil {
		return nil, fmt.Errorf("apply defaults: %w", err)
	}
	if path != "" {
		if err := loadYAML(path, &c); err != nil {
			return nil, err
		}
	}
	if err := env.Parse(&c); err != nil {
		return nil, fmt.Errorf("parse environment: %w", err)
	}
	if overlay != nil {
		if err := overlay(&c); err != nil {
			return nil, err
		}
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// LoadBackend builds a backend.Config: defaults → env → flag overlay. Used by
// the one-shot key-management commands, which take no YAML file.
func LoadBackend(overlay func(*backend.Config)) (backend.Config, error) {
	var c backend.Config
	if err := defaults.Set(&c); err != nil {
		return c, fmt.Errorf("apply defaults: %w", err)
	}
	if err := env.Parse(&c); err != nil {
		return c, fmt.Errorf("parse environment: %w", err)
	}
	if overlay != nil {
		overlay(&c)
	}
	return c, nil
}

// Validate checks the configuration is complete and consistent.
func (c *Config) Validate() error {
	if c.ChainID == "" {
		return fmt.Errorf("chain_id is required")
	}
	switch {
	case len(c.NodeAddrs) == 0 && c.NodeService == "":
		return fmt.Errorf("set either nodes (static list) or node_service (headless service)")
	case len(c.NodeAddrs) > 0 && c.NodeService != "":
		return fmt.Errorf("nodes and node_service are mutually exclusive")
	}
	switch c.Backend.Type {
	case backend.TypeSoftware, "":
		if c.Backend.SoftwareKeyFile == "" {
			return fmt.Errorf("software backend requires backend.key_file")
		}
	case backend.TypeVault:
		if c.Backend.Vault.KeyName == "" {
			return fmt.Errorf("vault backend requires backend.vault.key_name")
		}
		if c.Backend.Vault.TokenFile == "" {
			return fmt.Errorf("vault backend requires backend.vault.token_file")
		}
		if c.Backend.Vault.KeyVersion < 0 {
			return fmt.Errorf("vault backend key version must be zero or greater")
		}
	case backend.TypeGCPKMS:
		if c.Backend.GCPKMS.KeyVersion == "" {
			return fmt.Errorf("gcpkms backend requires backend.gcp.key_version")
		}
	default:
		return fmt.Errorf("unknown backend type %q", c.Backend.Type)
	}
	if c.Raft.NodeID == "" {
		return fmt.Errorf("raft.node_id is required")
	}
	if c.Raft.BindAddr == "" {
		return fmt.Errorf("raft.bind_addr is required")
	}
	if c.Raft.DataDir == "" {
		return fmt.Errorf("raft.data_dir is required")
	}
	// Mirror the raft store's bootstrap self-check at config level so a
	// misconfigured member list fails before any raft state is created.
	if c.Raft.Bootstrap && len(c.Raft.Members) > 0 {
		found := false
		for _, m := range c.Raft.Members {
			if m.ID == "" || m.Address == "" {
				return fmt.Errorf("raft member needs both id and address: %+v", m)
			}
			if m.ID == c.Raft.NodeID {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("raft.node_id %q is not in raft.members", c.Raft.NodeID)
		}
	}
	// Raft mTLS is all-or-nothing: a partial config (e.g. cert without CA) is a
	// mistake that would otherwise silently fall back to plain TCP.
	set := 0
	for _, f := range []string{c.Raft.TLSCert, c.Raft.TLSKey, c.Raft.TLSCA} {
		if f != "" {
			set++
		}
	}
	if set != 0 && set != 3 {
		return fmt.Errorf("raft TLS requires raft.tls_cert, raft.tls_key and raft.tls_ca together (or none)")
	}
	return nil
}
