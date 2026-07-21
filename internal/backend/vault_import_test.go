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
		case r.Method == http.MethodPut && r.URL.Path == "/v1/transit/sign/validator":
			writeVaultImportSignature(w, priv)
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

func TestVaultImportKeyIsIdempotentBelowMinimumSigningVersion(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	wrappingPEM := testVaultWrappingKey(t)

	var imports atomic.Int32
	var importVersions atomic.Int32
	var signs atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/transit/keys/validator":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"type": "ed25519", "latest_version": 2, "min_encryption_version": 2,
				"keys": map[string]any{"1": map[string]any{"public_key": base64.StdEncoding.EncodeToString(pub)}},
			}})
		case r.Method == http.MethodPut && r.URL.Path == "/v1/transit/sign/validator":
			signs.Add(1)
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{"version is below min_encryption_version"}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/transit/wrapping_key":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"public_key": string(wrappingPEM)}})
		case r.Method == http.MethodPut && r.URL.Path == "/v1/transit/keys/validator/import_version":
			importVersions.Add(1)
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{"private key imported, key version cannot be updated"}})
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
	require.Zero(t, imports.Load(), "an identical disabled key must still be accepted as an already-completed import")
	require.Equal(t, int32(1), importVersions.Load(), "the version endpoint must prove private material exists")
	require.Zero(t, signs.Load(), "import retry must not apply signer eligibility checks to a disabled existing version")
}

func TestVaultImportKeyCompletesMatchingPublicOnlyVersion(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	wrappingPEM := testVaultWrappingKey(t)

	var importedVersion atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/transit/keys/validator":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"type": "ed25519", "latest_version": 1,
				"keys": map[string]any{"1": map[string]any{"public_key": base64.StdEncoding.EncodeToString(pub)}},
			}})
		case r.Method == http.MethodPut && r.URL.Path == "/v1/transit/sign/validator":
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{"key version contains public key only"}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/transit/wrapping_key":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"public_key": string(wrappingPEM)}})
		case r.Method == http.MethodPut && r.URL.Path == "/v1/transit/keys/validator/import_version":
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			version, ok := payload["version"].(float64)
			if !ok {
				http.Error(w, "missing version", http.StatusBadRequest)
				return
			}
			importedVersion.Store(int32(version))
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cfg := VaultConfig{Address: server.URL, TokenFile: testVaultTokenFile(t), Mount: "transit", KeyName: "validator", KeyVersion: 1}
	require.NoError(t, VaultImportKey(cfg, pkcs8))
	require.Equal(t, int32(1), importedVersion.Load())
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
	wrappingPEM := testVaultWrappingKey(t)

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

func testVaultWrappingKey(t *testing.T) []byte {
	t.Helper()
	wrappingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	wrappingDER, err := x509.MarshalPKIXPublicKey(&wrappingKey.PublicKey)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: wrappingDER})
}

func writeVaultImportSignature(w http.ResponseWriter, privateKey ed25519.PrivateKey) {
	signature := ed25519.Sign(privateKey, vaultPreflightMessage)
	_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
		"signature": "vault:v1:" + base64.StdEncoding.EncodeToString(signature),
	}})
}
