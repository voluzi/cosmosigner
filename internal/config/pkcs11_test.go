package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPKCS11YAMLAndEnvironment(t *testing.T) {
	t.Setenv("COSMOSIGNER_PKCS11_TOKEN_LABEL", "")
	t.Setenv("COSMOSIGNER_PKCS11_SLOT", "")
	file := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(file, []byte(`chain_id: test
node_service: node:5555
backend:
  type: pkcs11
  pkcs11:
    module: yaml.so
    slot: 0
    key_label: validator
    pin_file: /pin
    binding_file: /binding
raft:
  insecure: true
`), 0600))
	cfg, err := Load(file, nil)
	require.NoError(t, err)
	require.NotNil(t, cfg.Backend.PKCS11.Slot)
	require.Zero(t, *cfg.Backend.PKCS11.Slot)
	t.Setenv("COSMOSIGNER_PKCS11_MODULE", "env.so")
	t.Setenv("COSMOSIGNER_PKCS11_SLOT", "7")
	cfg, err = Load(file, nil)
	require.NoError(t, err)
	require.Equal(t, "env.so", cfg.Backend.PKCS11.Module)
	require.Equal(t, uint(7), *cfg.Backend.PKCS11.Slot)
	t.Setenv("COSMOSIGNER_PKCS11_PIN_FILE", "")
	cfg.Backend.PKCS11.PINFile = ""
	require.ErrorContains(t, cfg.Validate(), "pin_file")
	cfg.Backend.PKCS11.PINFile = "/pin"
	cfg.Raft.Insecure = false
	require.ErrorContains(t, cfg.Validate(), "raft transport")
}
func TestPKCS11RejectsSecretYAML(t *testing.T) {
	for _, field := range []string{"pin", "pin_env"} {
		t.Run(field, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "config.yaml")
			require.NoError(t, os.WriteFile(file, []byte("backend:\n  type: pkcs11\n  pkcs11:\n    "+field+": secret\n"), 0600))
			_, err := Load(file, nil)
			require.ErrorContains(t, err, "field "+field+" not found")
		})
	}
}
