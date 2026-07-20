package backend

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/stretchr/testify/require"
)

func TestVaultExplicitKeyVersionDoesNotFollowLatest(t *testing.T) {
	versionOne := ed25519.GenPrivKey().PubKey().Bytes()
	versionTwo := ed25519.GenPrivKey().PubKey().Bytes()

	server := newVaultBackendServer(t, versionOne, versionTwo)
	v, err := NewVault(VaultConfig{
		Address:    server.URL,
		TokenFile:  writeVaultToken(t),
		Mount:      "transit",
		KeyName:    "validator",
		KeyVersion: 1,
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, v.Close()) })

	pub, err := v.PubKey()
	require.NoError(t, err)
	require.Equal(t, versionOne, pub.Bytes())
	require.Equal(t, 1, v.keyVersion)
}

func TestVaultKeyVersionZeroSelectsAndPinsLatest(t *testing.T) {
	versionOne := ed25519.GenPrivKey().PubKey().Bytes()
	versionTwo := ed25519.GenPrivKey().PubKey().Bytes()

	server := newVaultBackendServer(t, versionOne, versionTwo)
	v, err := NewVault(VaultConfig{
		Address:    server.URL,
		TokenFile:  writeVaultToken(t),
		Mount:      "transit",
		KeyName:    "validator",
		KeyVersion: 0,
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, v.Close()) })

	pub, err := v.PubKey()
	require.NoError(t, err)
	require.Equal(t, versionTwo, pub.Bytes())
	require.Equal(t, 2, v.keyVersion)
}

func TestVaultMissingRequestedKeyVersionFailsClosed(t *testing.T) {
	versionOne := ed25519.GenPrivKey().PubKey().Bytes()
	versionTwo := ed25519.GenPrivKey().PubKey().Bytes()
	server := newVaultBackendServer(t, versionOne, versionTwo)

	_, err := NewVault(VaultConfig{
		Address:    server.URL,
		TokenFile:  writeVaultToken(t),
		Mount:      "transit",
		KeyName:    "validator",
		KeyVersion: 3,
	})
	require.ErrorContains(t, err, "missing version 3")
}

func TestVaultPinnedVersionBelowMinimumEncryptionVersionFailsClosed(t *testing.T) {
	versionOne := ed25519.GenPrivKey().PubKey().Bytes()
	versionTwo := ed25519.GenPrivKey().PubKey().Bytes()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/transit/keys/validator":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"type": "ed25519", "latest_version": 2, "min_encryption_version": 2,
				"keys": map[string]any{
					"1": map[string]any{"public_key": base64.StdEncoding.EncodeToString(versionOne)},
					"2": map[string]any{"public_key": base64.StdEncoding.EncodeToString(versionTwo)},
				},
			}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/auth/token/lookup-self":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"ttl": 0, "renewable": false}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	_, err := NewVault(VaultConfig{
		Address: server.URL, TokenFile: writeVaultToken(t), Mount: "transit", KeyName: "validator", KeyVersion: 1,
	})
	require.ErrorContains(t, err, "minimum signing version 2")

	v, err := NewVault(VaultConfig{
		Address: server.URL, TokenFile: writeVaultToken(t), Mount: "transit", KeyName: "validator", KeyVersion: 2,
	})
	require.NoError(t, err)
	require.NoError(t, v.Close())
}

func TestVaultVerifyCanSignRejectsPublicOnlyKey(t *testing.T) {
	publicKey := ed25519.GenPrivKey().PubKey().Bytes()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/transit/keys/validator":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"type": "ed25519", "latest_version": 1,
				"keys": map[string]any{"1": map[string]any{"public_key": base64.StdEncoding.EncodeToString(publicKey)}},
			}})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/sys/capabilities-self":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"capabilities": []string{"update"}}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/auth/token/lookup-self":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"ttl": 0, "renewable": false}})
		case r.Method == http.MethodPut && r.URL.Path == "/v1/transit/sign/validator":
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{"key version contains public key only"}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	v, err := NewVault(VaultConfig{
		Address: server.URL, TokenFile: writeVaultToken(t), Mount: "transit", KeyName: "validator", KeyVersion: 1,
	})
	require.NoError(t, err)
	defer func() { require.NoError(t, v.Close()) }()

	require.ErrorContains(t, v.VerifyCanSign(), "cannot sign")
}

func newVaultBackendServer(t *testing.T, versionOne, versionTwo []byte) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/transit/keys/validator":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"type":           "ed25519",
				"latest_version": 2,
				"keys": map[string]any{
					"1": map[string]any{"public_key": base64.StdEncoding.EncodeToString(versionOne)},
					"2": map[string]any{"public_key": base64.StdEncoding.EncodeToString(versionTwo)},
				},
			}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/auth/token/lookup-self":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"ttl": 0, "renewable": false}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func writeVaultToken(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(path, []byte("test-token"), 0o600))
	return path
}
