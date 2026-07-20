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
	require.Equal(t, "node-1", d.Raft.NodeID)
	require.Equal(t, "127.0.0.1:7070", d.Raft.BindAddr)
}

func TestLoad_EnvOverridesFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "c.yaml")
	require.NoError(t, os.WriteFile(file, []byte(
		"chain_id: from-file\nnodes:\n  - 1.2.3.4:5555\nbackend:\n  key_file: /key.json\n"), 0o600))

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
	cfg, err := Load("", nil)
	require.NoError(t, err)
	require.Equal(t, []string{"a:5555", "b:5555"}, cfg.NodeAddrs)
	require.Equal(t, backend.TypeVault, cfg.Backend.Type)
	require.Equal(t, "val", cfg.Backend.Vault.KeyName)
	require.Equal(t, 7, cfg.Backend.Vault.KeyVersion)
	require.Equal(t, "cHVia2V5", cfg.ExpectedPublicKey)
}

func TestLoad_VaultKeyVersionFromYAML(t *testing.T) {
	file := filepath.Join(t.TempDir(), "c.yaml")
	require.NoError(t, os.WriteFile(file, []byte(
		"chain_id: c\nnodes: [a:5555]\nexpected_public_key: cHVia2V5\nbackend:\n  type: vault\n  vault:\n    token_file: /t\n    key_name: validator\n    key_version: 4\n"), 0o600))

	cfg, err := Load(file, nil)
	require.NoError(t, err)
	require.Equal(t, 4, cfg.Backend.Vault.KeyVersion)
	require.Equal(t, "cHVia2V5", cfg.ExpectedPublicKey)
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
