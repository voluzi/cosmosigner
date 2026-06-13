//go:build vault_integration

package backend

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/require"
)

// These tests run against a real Vault. Bring one up with the dev script and
// point VAULT_TOKEN at a root (or otherwise privileged) token:
//
//	scripts/vault-dev.sh up
//	VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root \
//	  go test -tags vault_integration -run Vault ./internal/backend/
//
// They mount a dedicated transit path so they don't disturb other state.

const itMount = "transit-it"

func vaultRoot(t *testing.T) (*vaultapi.Client, string) {
	t.Helper()
	addr := os.Getenv("VAULT_ADDR")
	if addr == "" {
		addr = "http://127.0.0.1:8200"
	}
	token := os.Getenv("VAULT_TOKEN")
	if token == "" {
		token = "root"
	}
	cfg := vaultapi.DefaultConfig()
	cfg.Address = addr
	c, err := vaultapi.NewClient(cfg)
	require.NoError(t, err)
	c.SetToken(token)
	if _, err := c.Sys().Health(); err != nil {
		t.Skipf("no reachable Vault at %s (%v) — run scripts/vault-dev.sh up", addr, err)
	}
	// Dedicated transit mount (idempotent).
	if err := c.Sys().Mount(itMount, &vaultapi.MountInput{Type: "transit"}); err != nil {
		// already mounted is fine
	}
	return c, addr
}

func writeToken(t *testing.T, token string) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(f, []byte(token), 0o600))
	return f
}

func mustCreateKey(t *testing.T, root *vaultapi.Client, name string) {
	t.Helper()
	_, err := root.Logical().Write(itMount+"/keys/"+name, map[string]any{"type": "ed25519"})
	require.NoError(t, err)
}

// TestVaultIntegration_TokenRenewal proves the renew loop keeps a short-lived
// token alive: a periodic 4s token would expire mid-test, but signing still
// works after 10s because cosmosigner renewed it.
func TestVaultIntegration_TokenRenewal(t *testing.T) {
	root, addr := vaultRoot(t)
	mustCreateKey(t, root, "renewtest")
	require.NoError(t, root.Sys().PutPolicy("it-signer", `
path "`+itMount+`/keys/*" { capabilities = ["read"] }
path "`+itMount+`/sign/*" { capabilities = ["update"] }`))

	sec, err := root.Auth().Token().Create(&vaultapi.TokenCreateRequest{
		Policies: []string{"it-signer"},
		Period:   "4s", // periodic → renewable, resets to 4s on each renew
	})
	require.NoError(t, err)
	tokenFile := writeToken(t, sec.Auth.ClientToken)

	v, err := NewVault(VaultConfig{Address: addr, TokenFile: tokenFile, Mount: itMount, KeyName: "renewtest"})
	require.NoError(t, err)
	defer v.Close()

	// Wait well past the original 4s TTL. Without renewal the token is dead.
	time.Sleep(10 * time.Second)

	sig, err := v.Sign([]byte("renewal-keeps-this-token-alive"))
	require.NoError(t, err, "token should have been renewed, not expired")
	require.Len(t, sig, 64)
}

// TestVaultIntegration_VerifyCanSign proves the startup preflight rejects a
// token without sign permission and accepts one with it.
func TestVaultIntegration_VerifyCanSign(t *testing.T) {
	root, addr := vaultRoot(t)
	mustCreateKey(t, root, "verifytest")

	// No sign capability — only read (so NewVault can still fetch the pubkey).
	require.NoError(t, root.Sys().PutPolicy("it-nosign", `
path "`+itMount+`/keys/*" { capabilities = ["read"] }`))
	noSign, err := root.Auth().Token().Create(&vaultapi.TokenCreateRequest{
		Policies: []string{"it-nosign"}, Period: "1h",
	})
	require.NoError(t, err)

	v, err := NewVault(VaultConfig{Address: addr, TokenFile: writeToken(t, noSign.Auth.ClientToken), Mount: itMount, KeyName: "verifytest"})
	require.NoError(t, err) // pubkey read works
	defer v.Close()
	err = v.VerifyCanSign()
	require.Error(t, err, "preflight must reject a token that cannot sign")
	require.Contains(t, err.Error(), "sign")

	// With sign capability — preflight passes.
	require.NoError(t, root.Sys().PutPolicy("it-cansign", `
path "`+itMount+`/keys/*" { capabilities = ["read"] }
path "`+itMount+`/sign/*" { capabilities = ["update"] }`))
	canSign, err := root.Auth().Token().Create(&vaultapi.TokenCreateRequest{
		Policies: []string{"it-cansign"}, Period: "1h",
	})
	require.NoError(t, err)

	v2, err := NewVault(VaultConfig{Address: addr, TokenFile: writeToken(t, canSign.Auth.ClientToken), Mount: itMount, KeyName: "verifytest"})
	require.NoError(t, err)
	defer v2.Close()
	require.NoError(t, v2.VerifyCanSign())
}
