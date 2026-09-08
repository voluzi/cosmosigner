package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/voluzi/cosmosigner/internal/backend"
)

func TestDefaults(t *testing.T) {
	d := Defaults()
	require.Equal(t, "./data/conn_key.json", d.ConnKey)
	require.Equal(t, 5*time.Second, d.ReconcileInterval)
	require.Equal(t, 3*time.Second, d.TimeoutReadWrite)
	require.Equal(t, backend.TypeSoftware, d.Backend.Type)
	require.Equal(t, "transit", d.Backend.Vault.Mount)
	require.Equal(t, "cosmosigner", d.Backend.Vault.BindingMount)
	require.Equal(t, "node-1", d.Raft.NodeID)
	require.Equal(t, "127.0.0.1:7070", d.Raft.BindAddr)
	require.False(t, d.Raft.Insecure)
	require.False(t, d.Raft.SingleNode)
}

func TestValidate_RequiresRaftTransportSecurity(t *testing.T) {
	cfg := Defaults()
	cfg.ChainID = "chain"
	cfg.NodeAddrs = []string{"node:5555"}
	cfg.Backend.SoftwareKeyFile = "/key.json"

	err := cfg.Validate()
	require.ErrorContains(t, err, "raft transport requires mTLS or explicit insecure opt-out")
}

func TestValidate_AllowsExplicitInsecureRaft(t *testing.T) {
	cfg := Defaults()
	cfg.ChainID = "chain"
	cfg.NodeAddrs = []string{"node:5555"}
	cfg.Backend.SoftwareKeyFile = "/key.json"
	cfg.Raft.Insecure = true

	require.NoError(t, cfg.Validate())
}

func TestValidate_RejectsImplicitSingleNodeBootstrap(t *testing.T) {
	cfg := Defaults()
	cfg.ChainID = "chain"
	cfg.NodeAddrs = []string{"node:5555"}
	cfg.Backend.SoftwareKeyFile = "/key.json"
	cfg.Raft.Insecure = true
	cfg.Raft.Bootstrap = true

	require.ErrorContains(t, cfg.Validate(), "raft.single_node")
}

func TestLoad_SingleNodeBootstrap(t *testing.T) {
	for _, tc := range []struct {
		name string
		raft string
		env  string
		want string
	}{
		{name: "missing opt-in", raft: "  bootstrap: true\n", want: "raft.single_node"},
		{name: "empty list", raft: "  bootstrap: true\n  members: []\n", want: "raft.single_node"},
		{name: "YAML opt-in", raft: "  bootstrap: true\n  single_node: true\n"},
		{name: "env opt-in", raft: "  bootstrap: true\n", env: "true"},
		{name: "env overrides YAML", raft: "  bootstrap: true\n  single_node: true\n", env: "false", want: "raft.single_node"},
		{name: "bare joiner", raft: "  bootstrap: false\n"},
		{name: "explicit members", raft: "  bootstrap: true\n  members: [{id: node-1, address: node-1:7070}, {id: node-2, address: node-2:7070}]\n"},
		{name: "self missing", raft: "  bootstrap: true\n  members: [{id: node-2, address: node-2:7070}]\n", want: "not in raft.members"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.env != "" {
				t.Setenv("COSMOSIGNER_RAFT_SINGLE_NODE", tc.env)
			}
			file := filepath.Join(t.TempDir(), "c.yaml")
			require.NoError(t, os.WriteFile(file, []byte(
				"chain_id: chain\nnode_service: sentries:5555\nbackend:\n  key_file: /key.json\nraft:\n  bind_addr: 0.0.0.0:7070\n  insecure: true\n"+tc.raft), 0o600))
			_, err := Load(file, nil)
			if tc.want != "" {
				require.ErrorContains(t, err, tc.want)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestValidate_AllowsRaftMTLS(t *testing.T) {
	cfg := Defaults()
	cfg.ChainID = "chain"
	cfg.NodeAddrs = []string{"node:5555"}
	cfg.Backend.SoftwareKeyFile = "/key.json"
	cfg.Raft.TLSCert = "/tls/cert.pem"
	cfg.Raft.TLSKey = "/tls/key.pem"
	cfg.Raft.TLSCA = "/tls/ca.pem"

	require.NoError(t, cfg.Validate())
}

func TestValidate_RejectsPartialRaftTLS(t *testing.T) {
	cfg := Defaults()
	cfg.ChainID = "chain"
	cfg.NodeAddrs = []string{"node:5555"}
	cfg.Backend.SoftwareKeyFile = "/key.json"
	cfg.Raft.TLSCert = "/tls/cert.pem"

	err := cfg.Validate()
	require.EqualError(t, err, "raft TLS requires raft.tls_cert, raft.tls_key and raft.tls_ca together (or remove all three and set raft.insecure: true for plain TCP)")
}

func TestValidate_RejectsInsecureRaftWithMTLS(t *testing.T) {
	cfg := Defaults()
	cfg.ChainID = "chain"
	cfg.NodeAddrs = []string{"node:5555"}
	cfg.Backend.SoftwareKeyFile = "/key.json"
	cfg.Raft.Insecure = true
	cfg.Raft.TLSCert = "/tls/cert.pem"
	cfg.Raft.TLSKey = "/tls/key.pem"
	cfg.Raft.TLSCA = "/tls/ca.pem"

	err := cfg.Validate()
	require.ErrorContains(t, err, "cannot enable both mTLS and raft.insecure")
}

func TestLoad_EnvOverridesFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "c.yaml")
	require.NoError(t, os.WriteFile(file, []byte(
		"chain_id: from-file\nnodes:\n  - 1.2.3.4:5555\nbackend:\n  key_file: /key.json\nraft:\n  insecure: true\n"), 0o600))

	t.Setenv("COSMOSIGNER_CHAIN_ID", "from-env")
	cfg, err := Load(file, nil)
	require.NoError(t, err)
	require.Equal(t, "from-env", cfg.ChainID)                 // env > file
	require.Equal(t, []string{"1.2.3.4:5555"}, cfg.NodeAddrs) // file
	require.Equal(t, "/key.json", cfg.Backend.SoftwareKeyFile)
}

func TestLoad_FlagOverlayWins(t *testing.T) {
	t.Setenv("COSMOSIGNER_CHAIN_ID", "from-env")
	cfg, err := Load("", func(c *Config) error {
		c.ChainID = "from-flag"
		c.NodeAddrs = []string{"x:1"}
		c.Backend.SoftwareKeyFile = "/k"
		c.Raft.Insecure = true
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, "from-flag", cfg.ChainID) // flag > env
}

func TestLoad_EnvBackendAndSlices(t *testing.T) {
	t.Setenv("COSMOSIGNER_CHAIN_ID", "c")
	t.Setenv("COSMOSIGNER_NODE", "a:5555,b:5555")
	t.Setenv("COSMOSIGNER_BACKEND", "vault")
	t.Setenv("COSMOSIGNER_VAULT_KEY", "val")
	t.Setenv("COSMOSIGNER_VAULT_KEY_VERSION", "7")
	t.Setenv("COSMOSIGNER_VAULT_TOKEN_FILE", "/t")
	t.Setenv("COSMOSIGNER_EXPECTED_PUBLIC_KEY", "cHVia2V5")
	t.Setenv("COSMOSIGNER_RAFT_INSECURE", "true")
	cfg, err := Load("", nil)
	require.NoError(t, err)
	require.Equal(t, []string{"a:5555", "b:5555"}, cfg.NodeAddrs)
	require.Equal(t, backend.TypeVault, cfg.Backend.Type)
	require.Equal(t, "val", cfg.Backend.Vault.KeyName)
	require.Equal(t, 7, cfg.Backend.Vault.KeyVersion)
	require.Equal(t, "cHVia2V5", cfg.ExpectedPublicKey)
	require.True(t, cfg.Raft.Insecure)
}

func TestLoad_VaultKeyVersionFromYAML(t *testing.T) {
	file := filepath.Join(t.TempDir(), "c.yaml")
	require.NoError(t, os.WriteFile(file, []byte(
		"chain_id: c\nnodes: [a:5555]\nexpected_public_key: cHVia2V5\nbackend:\n  type: vault\n  vault:\n    token_file: /t\n    key_name: validator\n    key_version: 4\n    binding_mount: from-file\nraft:\n  insecure: true\n"), 0o600))

	t.Setenv("COSMOSIGNER_VAULT_BINDING_MOUNT", "from-env")
	cfg, err := Load(file, nil)
	require.NoError(t, err)
	require.Equal(t, 4, cfg.Backend.Vault.KeyVersion)
	require.Equal(t, "cHVia2V5", cfg.ExpectedPublicKey)
	require.Equal(t, "from-env", cfg.Backend.Vault.BindingMount)
}

func TestValidateRejectsAmbiguousVaultAddressing(t *testing.T) {
	cfg := Defaults()
	cfg.ChainID = "chain"
	cfg.NodeAddrs = []string{"node:5555"}
	cfg.Raft.Insecure = true
	cfg.Backend.Type = backend.TypeVault
	cfg.Backend.Vault.TokenFile = "/token"
	cfg.Backend.Vault.KeyName = "validator/name"

	require.EqualError(t, cfg.Validate(), "vault key name \"validator/name\" contains an ambiguous path component")
}

func TestLoad_RejectsUnknownYAMLField(t *testing.T) {
	file := filepath.Join(t.TempDir(), "c.yaml")
	require.NoError(t, os.WriteFile(file, []byte(
		"chain_id: c\nnodes: [a:5555]\nbackend:\n  key_file: /k\nexpected_pubkey: silently-ignored-typo\n"), 0o600))

	_, err := Load(file, nil)
	require.ErrorContains(t, err, "field expected_pubkey not found")
}

func TestLoad_RejectsUnknownNestedYAMLField(t *testing.T) {
	file := filepath.Join(t.TempDir(), "c.yaml")
	require.NoError(t, os.WriteFile(file, []byte(
		"chain_id: c\nnodes: [a:5555]\nbackend:\n  type: vault\n  vault:\n    token_file: /t\n    key_name: validator\n    key_verison: 4\n"), 0o600))

	_, err := Load(file, nil)
	require.ErrorContains(t, err, "field key_verison not found")
}

func TestValidate_MutuallyExclusiveNodes(t *testing.T) {
	t.Setenv("COSMOSIGNER_CHAIN_ID", "c")
	_, err := Load("", func(c *Config) error {
		c.NodeAddrs = []string{"a:1"}
		c.NodeService = "svc:5555"
		c.Backend.SoftwareKeyFile = "/k"
		return nil
	})
	require.ErrorContains(t, err, "mutually exclusive")
}

func TestValidate_RequiresChainID(t *testing.T) {
	_, err := Load("", func(c *Config) error { c.NodeAddrs = []string{"a:1"}; return nil })
	require.ErrorContains(t, err, "chain_id")
}
