package backend

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

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

func TestVaultRenewLoopReloadsChangedTokenFile(t *testing.T) {
	privateKey := ed25519.GenPrivKey()
	firstLookup := make(chan struct{}, 1)
	replacementLookup := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/sys/capabilities-self":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"capabilities": []string{"update"}}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/auth/token/lookup-self":
			switch r.Header.Get("X-Vault-Token") {
			case "initial-token":
				select {
				case firstLookup <- struct{}{}:
				default:
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"ttl": 3600, "renewable": true}})
			case "replacement-token":
				select {
				case replacementLookup <- struct{}{}:
				default:
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"ttl": 0, "renewable": false}})
			default:
				http.Error(w, "unexpected token", http.StatusForbidden)
			}
		case r.Method == http.MethodPut && r.URL.Path == "/v1/auth/token/renew-self":
			_ = json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{"lease_duration": 2, "renewable": true}})
		case r.Method == http.MethodPut && r.URL.Path == "/v1/transit/sign/validator":
			var request map[string]any
			require.NoError(t, json.NewDecoder(r.Body).Decode(&request))
			input, err := base64.StdEncoding.DecodeString(request["input"].(string))
			require.NoError(t, err)
			signature, err := privateKey.Sign(input)
			require.NoError(t, err)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"signature": "vault:v1:" + base64.StdEncoding.EncodeToString(signature),
			}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	tokenFile := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(tokenFile, []byte("initial-token"), 0o600))
	client, err := NewVaultClient(VaultConfig{Address: server.URL, TokenFile: tokenFile})
	require.NoError(t, err)
	v := &Vault{
		client: client, mount: "transit", keyName: "validator", keyVersion: 1, pub: privateKey.PubKey(),
		tokenFile: tokenFile, stopRenew: make(chan struct{}),
	}
	t.Cleanup(func() { require.NoError(t, v.Close()) })
	go v.renewLoopWithPollInterval(10 * time.Millisecond)

	select {
	case <-firstLookup:
	case <-time.After(2 * time.Second):
		t.Fatal("renew loop did not inspect the initial token")
	}
	require.NoError(t, os.WriteFile(tokenFile, []byte("replacement-token"), 0o600))

	select {
	case <-replacementLookup:
	case <-time.After(3 * time.Second):
		t.Fatal("renew loop did not reload the changed token file")
	}
	require.Eventually(t, func() bool { return client.Token() == "replacement-token" }, 250*time.Millisecond, 10*time.Millisecond)
}

func TestVaultRenewLoopRejectsFiniteNonRenewableReplacementToken(t *testing.T) {
	replacementLookup := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/sys/capabilities-self":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"capabilities": []string{"update"}}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/auth/token/lookup-self":
			switch r.Header.Get("X-Vault-Token") {
			case "initial-token":
				_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"ttl": 3600, "renewable": true}})
			case "replacement-token":
				_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"ttl": 60, "renewable": false}})
				select {
				case replacementLookup <- struct{}{}:
				default:
				}
			default:
				http.Error(w, "unexpected token", http.StatusForbidden)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	tokenFile := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(tokenFile, []byte("initial-token"), 0o600))
	client, err := NewVaultClient(VaultConfig{Address: server.URL, TokenFile: tokenFile})
	require.NoError(t, err)
	v := &Vault{
		client: client, mount: "transit", keyName: "validator", keyVersion: 1,
		tokenFile: tokenFile, stopRenew: make(chan struct{}),
	}
	t.Cleanup(func() { require.NoError(t, v.Close()) })
	go v.renewLoopWithPollInterval(10 * time.Millisecond)

	require.NoError(t, os.WriteFile(tokenFile, []byte("replacement-token"), 0o600))
	select {
	case <-replacementLookup:
	case <-time.After(2 * time.Second):
		t.Fatal("renew loop did not inspect the replacement token")
	}
	require.Eventually(t, func() bool { return client.Token() == "initial-token" }, 250*time.Millisecond, 10*time.Millisecond)
}

func TestVaultRenewLoopValidatesReplacementTokenBeforeAdopting(t *testing.T) {
	privateKey := ed25519.GenPrivKey()
	replacementSigned := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/sys/capabilities-self":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"capabilities": []string{"update"}}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/auth/token/lookup-self":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"ttl": 3600, "renewable": true}})
		case r.Method == http.MethodPut && r.URL.Path == "/v1/transit/sign/validator":
			var request map[string]any
			require.NoError(t, json.NewDecoder(r.Body).Decode(&request))
			input, err := base64.StdEncoding.DecodeString(request["input"].(string))
			require.NoError(t, err)
			signature, err := privateKey.Sign(input)
			require.NoError(t, err)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"signature": "vault:v1:" + base64.StdEncoding.EncodeToString(signature),
			}})
			select {
			case replacementSigned <- struct{}{}:
			default:
			}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	tokenFile := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(tokenFile, []byte("initial-token"), 0o600))
	client, err := NewVaultClient(VaultConfig{Address: server.URL, TokenFile: tokenFile})
	require.NoError(t, err)
	v := &Vault{
		client: client, mount: "transit", keyName: "validator", keyVersion: 1, pub: privateKey.PubKey(),
		tokenFile: tokenFile, stopRenew: make(chan struct{}),
	}
	t.Cleanup(func() { require.NoError(t, v.Close()) })
	go v.renewLoopWithPollInterval(10 * time.Millisecond)

	require.NoError(t, os.WriteFile(tokenFile, []byte("replacement-token"), 0o600))
	select {
	case <-replacementSigned:
	case <-time.After(2 * time.Second):
		t.Fatal("renew loop adopted the replacement token without proving that it can sign")
	}
	require.Eventually(t, func() bool { return client.Token() == "replacement-token" }, 250*time.Millisecond, 10*time.Millisecond)
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
