package cmd

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cometbft/cometbft/crypto/ed25519"
	cmtlog "github.com/cometbft/cometbft/libs/log"
	"github.com/cometbft/cometbft/privval"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"

	"github.com/voluzi/cosmosigner/internal/backend"
	"github.com/voluzi/cosmosigner/internal/config"
)

// healthTestStatus mirrors the documented /status body. Decoding rejects unknown fields, so a field
// added to the endpoint fails these tests until it is reviewed here.
type healthTestStatus struct {
	Version string `json:"version"`
	ChainID string `json:"chain_id"`
	Raft    struct {
		NodeID string `json:"node_id"`
		State  string `json:"state"`
		Leader bool   `json:"leader"`
	} `json:"raft"`
	Ready bool `json:"ready"`
	Nodes []struct {
		Address      string     `json:"address"`
		Connected    bool       `json:"connected"`
		LastActivity *time.Time `json:"last_activity"`
	} `json:"nodes"`
}

// healthGet returns the status code and body, or code 0 while the endpoint is not reachable.
func healthGet(addr, path string) (int, []byte) {
	client := http.Client{Timeout: 5 * time.Second}
	res, err := client.Get("http://" + addr + path)
	if err != nil {
		return 0, nil
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return 0, nil
	}
	return res.StatusCode, body
}

func healthStatus(t *testing.T, addr string) (healthTestStatus, bool) {
	t.Helper()
	code, body := healthGet(addr, "/status")
	if code != http.StatusOK {
		return healthTestStatus{}, false
	}
	var status healthTestStatus
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	require.NoError(t, decoder.Decode(&status), "unexpected /status body: %s", body)
	return status, true
}

// healthTestConfig is a single-node signer that claims its freshly generated software key at
// startup, with the health endpoints on their own port.
func healthTestConfig(t *testing.T, nodeAddr string) config.Config {
	t.Helper()
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "priv_validator_key.json")
	pv := privval.GenFilePV(keyFile, filepath.Join(dir, "priv_validator_state.json"))
	pv.Key.Save()
	addresses := startTestAddresses(t, 2)

	cfg := config.Defaults()
	cfg.ChainID = "chain"
	cfg.LogLevel = "error"
	cfg.NodeAddrs = []string{nodeAddr}
	cfg.ConnKey = filepath.Join(dir, "conn_key.json")
	cfg.HTTPAddr = addresses[1]
	cfg.Backend.SoftwareKeyFile = keyFile
	cfg.ClaimIfUnclaimed = true
	cfg.Raft.NodeID = "node-1"
	cfg.Raft.BindAddr = addresses[0]
	cfg.Raft.Advertise = addresses[0]
	cfg.Raft.DataDir = filepath.Join(dir, "raft")
	cfg.Raft.Bootstrap = true
	cfg.Raft.SingleNode = true
	cfg.Raft.Insecure = true
	return cfg
}

// gatedPreflightBackend holds the startup preflight open until released.
type gatedPreflightBackend struct {
	backend.KeyBackend
	started chan struct{}
	release chan struct{}
}

func (b *gatedPreflightBackend) VerifyCanSign(ctx context.Context) error {
	close(b.started)
	select {
	case <-b.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestHealth_LivezBeforeBackendAndReadyzAfterPreflight(t *testing.T) {
	cfg := healthTestConfig(t, "127.0.0.1:1")
	cfg.HTTPAddr = "127.0.0.1:0"
	logger := cmtlog.NewNopLogger()
	hs, err := startHealthServer(cfg, logger)
	require.NoError(t, err)
	defer hs.Close()

	// Nothing but the HTTP server exists yet: no backend, no raft.
	code, _ := healthGet(hs.Addr(), "/livez")
	require.Equal(t, http.StatusOK, code)
	code, _ = healthGet(hs.Addr(), "/readyz")
	require.Equal(t, http.StatusServiceUnavailable, code)

	software, err := backend.NewSoftware(cfg.Backend.SoftwareKeyFile)
	require.NoError(t, err)
	defer software.Close()
	be := &gatedPreflightBackend{KeyBackend: software, started: make(chan struct{}), release: make(chan struct{})}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- runStartWithContext(ctx, cfg, false, &bytes.Buffer{}, be, hs, logger, hclog.NewNullLogger())
	}()

	select {
	case <-be.started:
	case err := <-done:
		t.Fatalf("signer exited before the preflight: %v", err)
	case <-time.After(20 * time.Second):
		t.Fatal("preflight did not start")
	}
	// Raft is open and leading, but the backend has not proven it can sign.
	code, _ = healthGet(hs.Addr(), "/livez")
	require.Equal(t, http.StatusOK, code)
	code, _ = healthGet(hs.Addr(), "/readyz")
	require.Equal(t, http.StatusServiceUnavailable, code, "not ready while the backend preflight is pending")

	close(be.release)
	require.Eventually(t, func() bool {
		code, _ := healthGet(hs.Addr(), "/readyz")
		return code == http.StatusOK
	}, 20*time.Second, 20*time.Millisecond, "ready once the preflight passed")

	cancel()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(20 * time.Second):
		t.Fatal("signer did not stop")
	}
	code, _ = healthGet(hs.Addr(), "/readyz")
	require.Equal(t, http.StatusServiceUnavailable, code, "not ready after shutdown")
	code, _ = healthGet(hs.Addr(), "/livez")
	require.Equal(t, http.StatusOK, code)
}

func TestHealth_FollowerReadyAndStatusReportsLeader(t *testing.T) {
	if testing.Short() {
		t.Skip("multi-node Raft lifecycle test")
	}
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "priv_validator_key.json")
	pv := privval.GenFilePV(keyFile, filepath.Join(dir, "priv_validator_state.json"))
	pv.Key.Save()

	// One node, listening, so the leader has a connection to report.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	node := privval.NewSignerListenerEndpoint(cmtlog.NewNopLogger(),
		privval.NewTCPListener(ln, ed25519.GenPrivKey()),
		privval.SignerListenerEndpointTimeoutReadWrite(2*time.Second))
	require.NoError(t, node.Start())
	t.Cleanup(func() { _ = node.Stop() })
	nodeAddr := ln.Addr().String()

	addresses := startTestAddresses(t, 6)
	raftAddrs, httpAddrs := addresses[:3], addresses[3:]
	members := make([]config.Member, 3)
	for i := range members {
		members[i] = config.Member{ID: fmt.Sprintf("node-%d", i), Address: raftAddrs[i]}
	}
	results := make([]chan error, 3)
	cancels := make([]context.CancelFunc, 3)
	for i := range results {
		cfg := config.Defaults()
		cfg.ChainID = "chain"
		cfg.LogLevel = "error"
		cfg.NodeAddrs = []string{nodeAddr}
		cfg.ConnKey = filepath.Join(dir, members[i].ID, "conn_key.json")
		cfg.HTTPAddr = httpAddrs[i]
		cfg.Backend.SoftwareKeyFile = keyFile
		cfg.ClaimIfUnclaimed = true
		cfg.ReconcileInterval = 200 * time.Millisecond
		cfg.Raft.NodeID = members[i].ID
		cfg.Raft.BindAddr = raftAddrs[i]
		cfg.Raft.Advertise = raftAddrs[i]
		cfg.Raft.DataDir = filepath.Join(dir, members[i].ID, "raft")
		cfg.Raft.Bootstrap = i == 0
		cfg.Raft.Insecure = true
		cfg.Raft.Members = members
		ctx, cancel := context.WithCancel(t.Context())
		cancels[i] = cancel
		results[i] = make(chan error, 1)
		go func() {
			results[i] <- runStartModeContext(ctx, cfg, false, &bytes.Buffer{})
		}()
	}
	t.Cleanup(func() {
		for _, cancel := range cancels {
			cancel()
		}
		for i := range results {
			select {
			case err := <-results[i]:
				require.NoError(t, err, "replica %d did not shut down cleanly", i)
			case <-time.After(20 * time.Second):
				t.Errorf("replica %d did not stop after cancellation", i)
			}
		}
	})

	statuses := make([]healthTestStatus, 3)
	require.Eventually(t, func() bool {
		leaders := 0
		for i, addr := range httpAddrs {
			if code, _ := healthGet(addr, "/readyz"); code != http.StatusOK {
				return false
			}
			status, ok := healthStatus(t, addr)
			if !ok {
				return false
			}
			statuses[i] = status
			if status.Raft.Leader {
				leaders++
				if len(status.Nodes) != 1 || !status.Nodes[0].Connected {
					return false
				}
			}
		}
		return leaders == 1
	}, 60*time.Second, 50*time.Millisecond, "every replica must be ready and exactly one must lead and serve the node")

	for i, status := range statuses {
		require.True(t, status.Ready, "replica %d", i)
		require.Equal(t, members[i].ID, status.Raft.NodeID)
		require.Equal(t, "chain", status.ChainID)
		if !status.Raft.Leader {
			require.Equal(t, "follower", status.Raft.State)
			require.Empty(t, status.Nodes, "a follower holds no node connections")
			continue
		}
		require.Equal(t, "leader", status.Raft.State)
		require.Equal(t, nodeAddr, status.Nodes[0].Address)
		require.NotNil(t, status.Nodes[0].LastActivity)
		require.WithinDuration(t, time.Now(), *status.Nodes[0].LastActivity, time.Minute)
	}
}

func TestHealth_StatusOmitsSecrets(t *testing.T) {
	cfg := healthTestConfig(t, "127.0.0.1:1")
	software, err := backend.NewSoftware(cfg.Backend.SoftwareKeyFile)
	require.NoError(t, err)
	pub, err := software.PubKey()
	require.NoError(t, err)
	require.NoError(t, software.Close())
	cfg.ExpectedPublicKey = base64.StdEncoding.EncodeToString(pub.Bytes())
	// Unused by the software backend, but part of the configuration the endpoint could echo.
	cfg.Backend.Vault.TokenFile = filepath.Join(t.TempDir(), "vault-token")
	cfg.Backend.Vault.KeyName = "validator-key-name"

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- runStartModeContext(ctx, cfg, false, &bytes.Buffer{}) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			require.NoError(t, err)
		case <-time.After(20 * time.Second):
			t.Error("signer did not stop")
		}
	})

	// Wait for the fullest body the endpoint produces: a ready leader with a node in its set.
	var status healthTestStatus
	require.Eventually(t, func() bool {
		var ok bool
		status, ok = healthStatus(t, cfg.HTTPAddr)
		return ok && status.Ready && status.Raft.Leader && len(status.Nodes) == 1
	}, 30*time.Second, 50*time.Millisecond)
	require.Equal(t, "127.0.0.1:1", status.Nodes[0].Address)
	require.False(t, status.Nodes[0].Connected)
	require.Nil(t, status.Nodes[0].LastActivity)

	claimed, err := backend.NewSoftware(cfg.Backend.SoftwareKeyFile)
	require.NoError(t, err)
	clusterID, err := claimed.ClusterBinding(t.Context())
	require.NoError(t, err)
	require.NoError(t, claimed.Close())
	_, body := healthGet(cfg.HTTPAddr, "/status")
	for name, secret := range map[string]string{
		"key file":          cfg.Backend.SoftwareKeyFile,
		"token file":        cfg.Backend.Vault.TokenFile,
		"key name":          cfg.Backend.Vault.KeyName,
		"conn key":          cfg.ConnKey,
		"raft data dir":     cfg.Raft.DataDir,
		"raft address":      cfg.Raft.BindAddr,
		"backend type":      string(cfg.Backend.Type),
		"cluster ID":        clusterID,
		"public key":        cfg.ExpectedPublicKey,
		"public key hex":    hex.EncodeToString(pub.Bytes()),
		"validator address": hex.EncodeToString(pub.Address()),
	} {
		require.NotEmpty(t, secret, name)
		require.NotContains(t, strings.ToLower(string(body)), strings.ToLower(secret), "/status must not expose the %s", name)
	}
}
