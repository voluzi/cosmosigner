package backend

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVaultImportKeyIsIdempotentForMatchingExistingVersion(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)

	var imports atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/transit/keys/validator":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"type": "ed25519", "latest_version": 1,
				"keys": map[string]any{"1": map[string]any{"public_key": base64.StdEncoding.EncodeToString(pub)}},
			}})
		case r.Method == http.MethodPut && r.URL.Path == "/v1/transit/keys/validator/import":
			imports.Add(1)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cfg := VaultConfig{Address: server.URL, TokenFile: testVaultTokenFile(t), Mount: "transit", KeyName: "validator", KeyVersion: 1}
	require.NoError(t, VaultImportKey(cfg, pkcs8))
	require.Zero(t, imports.Load(), "an identical existing key must not be submitted to the create-only import endpoint")
}

func TestVaultImportKeyRefusesDifferentExistingKey(t *testing.T) {
	_, sourcePriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(sourcePriv)
	require.NoError(t, err)
	existingPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	var imports atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/transit/keys/validator":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"type": "ed25519", "latest_version": 1,
				"keys": map[string]any{"1": map[string]any{"public_key": base64.StdEncoding.EncodeToString(existingPub)}},
			}})
		case r.Method == http.MethodPut && r.URL.Path == "/v1/transit/keys/validator/import":
			imports.Add(1)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cfg := VaultConfig{Address: server.URL, TokenFile: testVaultTokenFile(t), Mount: "transit", KeyName: "validator", KeyVersion: 1}
	err = VaultImportKey(cfg, pkcs8)
	require.ErrorContains(t, err, "different public key")
	require.Zero(t, imports.Load(), "a different existing identity must never be overwritten")
}

func TestVaultImportKeyCreatesMissingVersionOne(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	wrappingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	wrappingDER, err := x509.MarshalPKIXPublicKey(&wrappingKey.PublicKey)
	require.NoError(t, err)
	wrappingPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: wrappingDER})

	var imports atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/transit/keys/validator":
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/transit/wrapping_key":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"public_key": string(wrappingPEM)}})
		case r.Method == http.MethodPut && r.URL.Path == "/v1/transit/keys/validator/import":
			imports.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cfg := VaultConfig{Address: server.URL, TokenFile: testVaultTokenFile(t), Mount: "transit", KeyName: "validator", KeyVersion: 1}
	require.NoError(t, VaultImportKey(cfg, pkcs8))
	require.Equal(t, int32(1), imports.Load())
}

func TestVaultImportKeyRejectsMissingVersionAfterOne(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{}})
	}))
	defer server.Close()

	cfg := VaultConfig{Address: server.URL, TokenFile: testVaultTokenFile(t), Mount: "transit", KeyName: "validator", KeyVersion: 2}
	require.ErrorContains(t, VaultImportKey(cfg, pkcs8), "create key version 1")
}

func testVaultTokenFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(path, []byte("test-token"), 0o600))
	return path
}
