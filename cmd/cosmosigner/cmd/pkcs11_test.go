package cmd

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/voluzi/cosmosigner/internal/backend"
	"github.com/voluzi/cosmosigner/internal/config"
)

func TestPKCS11FlagPrecedence(t *testing.T) {
	t.Setenv("COSMOSIGNER_BACKEND", "pkcs11")
	t.Setenv("COSMOSIGNER_PKCS11_MODULE", "env.so")
	t.Setenv("COSMOSIGNER_PKCS11_SLOT", "9")
	t.Setenv("COSMOSIGNER_PKCS11_KEY_ID", "aabb")
	cmd := &cobra.Command{}
	registerBackendFlags(cmd)
	require.NoError(t, cmd.Flags().Parse([]string{"--pkcs11-module=flag.so", "--pkcs11-slot=0", "--pkcs11-key-label=validator"}))
	cfg, err := config.LoadBackend(func(c *backend.Config) { overlayBackendFlags(cmd, c) })
	require.NoError(t, err)
	require.Equal(t, backend.TypePKCS11, cfg.Type)
	require.Equal(t, "flag.so", cfg.PKCS11.Module)
	require.NotNil(t, cfg.PKCS11.Slot)
	require.Zero(t, *cfg.PKCS11.Slot)
	require.Equal(t, "aabb", cfg.PKCS11.KeyID)
	require.Equal(t, "validator", cfg.PKCS11.KeyLabel)
	for _, secretFlag := range []string{"pkcs11-pin", "pkcs11-pin-env"} {
		require.Nil(t, cmd.Flags().Lookup(secretFlag))
	}
}
func TestPKCS11ManagementUnsupported(t *testing.T) {
	for _, cmd := range []*cobra.Command{NewProvisionCmd(), NewImportCmd()} {
		cmd.SetArgs([]string{"--backend=pkcs11"})
		require.ErrorContains(t, cmd.Execute(), "not supported")
	}
}
