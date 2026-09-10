package backend

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/stretchr/testify/require"
)

type vaultBindingServer struct {
	mu                  sync.Mutex
	record              map[string]any
	tombstoned          bool
	writes              int
	lastPayload         map[string]any
	privateKey          ed25519.PrivKey
	failWriteAfterStore bool
	responseMetadata    map[string]any
}

func (s *vaultBindingServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Header.Get("X-Vault-Namespace") != "tenant-a" {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{"wrong namespace"}})
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/v1/team/transit/keys/validator":
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"type": "ed25519", "latest_version": 1,
			"keys": map[string]any{"1": map[string]any{"public_key": base64.StdEncoding.EncodeToString(s.privateKey.PubKey().Bytes())}},
		}})
	case r.Method == http.MethodGet && r.URL.Path == "/v1/registry/data/cluster-bindings/"+vaultBindingAddress("team/transit", "validator"):
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.record == nil && !s.tombstoned {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{"not found"}})
			return
		}
		metadata := map[string]any{"deletion_time": "", "destroyed": false}
		if s.responseMetadata != nil {
			metadata = make(map[string]any, len(s.responseMetadata))
			for key, value := range s.responseMetadata {
				metadata[key] = value
			}
		}
		var data any = s.record
		if s.tombstoned {
			data = nil
			metadata["deletion_time"] = "2026-09-08T00:00:00Z"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": data, "metadata": metadata}})
	case r.Method == http.MethodGet && r.URL.Path == "/v1/registry/metadata/cluster-bindings/"+vaultBindingAddress("team/transit", "validator"):
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.record == nil && !s.tombstoned {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{"not found"}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"current_version": 1}})
	case r.Method == http.MethodPut && r.URL.Path == "/v1/registry/data/cluster-bindings/"+vaultBindingAddress("team/transit", "validator"):
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		s.writes++
		s.lastPayload = payload
		if s.record != nil || s.tombstoned {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{"check-and-set parameter did not match current version"}})
			return
		}
		s.record, _ = payload["data"].(map[string]any)
		if s.failWriteAfterStore {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{"connection outcome unknown"}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"version": 1}})
	default:
		http.NotFound(w, r)
	}
}

func newVaultBindingBackend(t *testing.T, state *vaultBindingServer) *Vault {
	t.Helper()
	state.privateKey = ed25519.GenPrivKey()
	server := httptest.NewServer(state)
	t.Cleanup(server.Close)
	v, err := NewVault(VaultConfig{
		Address: server.URL, TokenFile: writeVaultToken(t), Mount: "/team/transit/",
		BindingMount: "/registry/", KeyName: "validator", Namespace: "tenant-a",
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, v.Close()) })
	return v
}

func TestVaultBindingClaimUsesCASZeroAndReadsExactResource(t *testing.T) {
	state := &vaultBindingServer{}
	v := newVaultBindingBackend(t, state)

	_, err := v.ClusterBinding(t.Context())
	require.ErrorIs(t, err, ErrBindingUnclaimed)
	require.Zero(t, state.writes, "runtime reads must not claim")
	require.NoError(t, v.ClaimCluster(t.Context(), clusterA))
	require.NoError(t, v.ClaimCluster(t.Context(), clusterA))
	owner, err := v.ClusterBinding(t.Context())
	require.NoError(t, err)
	require.Equal(t, clusterA, owner)

	state.mu.Lock()
	defer state.mu.Unlock()
	require.Equal(t, 1, state.writes, "same-owner retry must not overwrite")
	options, ok := state.lastPayload["options"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, float64(0), options["cas"])
	require.Equal(t, "team/transit", state.record["transit_mount"])
	require.Equal(t, "validator", state.record["key_name"])
}

func TestVaultBindingRejectsDifferentOwnerAndTombstone(t *testing.T) {
	state := &vaultBindingServer{}
	v := newVaultBindingBackend(t, state)
	require.NoError(t, v.ClaimCluster(t.Context(), clusterA))
	require.ErrorIs(t, v.ClaimCluster(t.Context(), clusterB), ErrBindingMismatch)

	state.mu.Lock()
	state.record = nil
	state.tombstoned = true
	state.mu.Unlock()
	_, err := v.ClusterBinding(t.Context())
	require.ErrorIs(t, err, ErrBindingCorrupt)
	require.ErrorIs(t, v.ClaimCluster(t.Context(), clusterA), ErrBindingCorrupt)
}

func TestVaultBindingConcurrentClaimsDoNotOverwrite(t *testing.T) {
	state := &vaultBindingServer{}
	v := newVaultBindingBackend(t, state)
	errs := make(chan error, 2)
	go func() { errs <- v.ClaimCluster(t.Context(), clusterA) }()
	go func() { errs <- v.ClaimCluster(t.Context(), clusterB) }()
	first, second := <-errs, <-errs
	require.True(t, (first == nil) != (second == nil))
	if first != nil {
		require.ErrorIs(t, first, ErrBindingMismatch)
	}
	if second != nil {
		require.ErrorIs(t, second, ErrBindingMismatch)
	}
	require.GreaterOrEqual(t, state.writes, 1)
	owner, err := v.ClusterBinding(t.Context())
	require.NoError(t, err)
	require.Contains(t, []string{clusterA, clusterB}, owner)
}

func TestVaultBindingAcceptsDurableIdenticalClaimAfterUncertainWrite(t *testing.T) {
	state := &vaultBindingServer{failWriteAfterStore: true}
	v := newVaultBindingBackend(t, state)
	require.NoError(t, v.ClaimCluster(t.Context(), clusterA))
	owner, err := v.ClusterBinding(t.Context())
	require.NoError(t, err)
	require.Equal(t, clusterA, owner)
}

func TestVaultBindingRejectsMalformedRecords(t *testing.T) {
	for _, record := range []map[string]any{
		{"version": 2, "cluster_id": clusterA, "transit_mount": "team/transit", "key_name": "validator"},
		{"version": 1, "cluster_id": "bad", "transit_mount": "team/transit", "key_name": "validator"},
		{"version": 1, "cluster_id": clusterA, "transit_mount": "other", "key_name": "validator"},
		{"version": 1, "cluster_id": clusterA, "transit_mount": "team/transit"},
	} {
		state := &vaultBindingServer{record: record}
		v := newVaultBindingBackend(t, state)
		_, err := v.ClusterBinding(t.Context())
		require.ErrorIs(t, err, ErrBindingCorrupt)
	}
}

func TestVaultBindingRejectsMissingOrWrongTypedVersionMetadata(t *testing.T) {
	record := map[string]any{
		"version": 1, "cluster_id": clusterA, "transit_mount": "team/transit", "key_name": "validator",
	}
	for _, tc := range []struct {
		name     string
		metadata map[string]any
	}{
		{name: "missing destroyed", metadata: map[string]any{"deletion_time": ""}},
		{name: "wrong destroyed type", metadata: map[string]any{"destroyed": "false", "deletion_time": ""}},
		{name: "missing deletion time", metadata: map[string]any{"destroyed": false}},
		{name: "wrong deletion time type", metadata: map[string]any{"destroyed": false, "deletion_time": nil}},
		{name: "destroyed", metadata: map[string]any{"destroyed": true, "deletion_time": ""}},
		{name: "deleted", metadata: map[string]any{"destroyed": false, "deletion_time": "2026-09-08T00:00:00Z"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := &vaultBindingServer{record: record, responseMetadata: tc.metadata}
			v := newVaultBindingBackend(t, state)

			_, err := v.ClusterBinding(t.Context())
			require.ErrorIs(t, err, ErrBindingCorrupt)
		})
	}
}
