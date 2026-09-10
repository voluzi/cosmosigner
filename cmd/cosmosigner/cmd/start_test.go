package cmd

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/privval"
	"github.com/stretchr/testify/require"

	"github.com/voluzi/cosmosigner/internal/backend"
	"github.com/voluzi/cosmosigner/internal/clusterid"
	"github.com/voluzi/cosmosigner/internal/config"
	"github.com/voluzi/cosmosigner/internal/state"
)

const startTestClusterID = "3b12f1df-5232-4804-897e-917bf397618a"

func TestParseMembers_Valid(t *testing.T) {
	members, err := parseMembers([]string{"a=1.2.3.4:7070", "b=5.6.7.8:7070"})
	require.NoError(t, err)
	require.Equal(t, []config.Member{
		{ID: "a", Address: "1.2.3.4:7070"},
		{ID: "b", Address: "5.6.7.8:7070"},
	}, members)
}

// Surrounding whitespace around the entry and around id/address is trimmed so
// values like " n0 = cs-0:7070 " don't carry spaces into the member set.
func TestParseMembers_TrimsWhitespace(t *testing.T) {
	members, err := parseMembers([]string{" a = 1.2.3.4:7070 ", "\tb\t=\t5.6.7.8:7070\t"})
	require.NoError(t, err)
	require.Equal(t, []config.Member{
		{ID: "a", Address: "1.2.3.4:7070"},
		{ID: "b", Address: "5.6.7.8:7070"},
	}, members)
}

// A whitespace-only id or address is empty after trimming and must fail closed.
func TestParseMembers_WhitespaceOnlyPiecesFail(t *testing.T) {
	_, err := parseMembers([]string{" = 1.2.3.4:7070"})
	require.Error(t, err)

	_, err = parseMembers([]string{"a =  "})
	require.Error(t, err)
}

// A malformed entry must not be silently dropped: parsing fails fast so a
// member list that would otherwise collapse to empty (and bootstrap a
// single-node cluster — a double-signing hazard) is rejected before startup.
func TestParseMembers_MissingEquals(t *testing.T) {
	_, err := parseMembers([]string{"a-1.2.3.4:7070"})
	require.Error(t, err)
}

func TestParseMembers_EmptyID(t *testing.T) {
	_, err := parseMembers([]string{"=1.2.3.4:7070"})
	require.Error(t, err)
}

func TestParseMembers_EmptyAddress(t *testing.T) {
	_, err := parseMembers([]string{"a="})
	require.Error(t, err)
}

// Even when every entry is malformed the result must be an error, never an
// empty (silently single-node) member set.
func TestParseMembers_AllMalformedNotIgnored(t *testing.T) {
	_, err := parseMembers([]string{"a-1.2.3.4", "b-5.6.7.8"})
	require.Error(t, err)
}

// Command setup must fail before startup when --raft-member is malformed.
func TestOverlayStartFlags_MalformedMemberFails(t *testing.T) {
	cmd := NewStartCmd()
	require.NoError(t, cmd.Flags().Set("raft-member", "no-equals-sign"))

	err := overlayStartFlags(cmd, &config.Config{})
	require.Error(t, err)
}

func TestOverlayStartFlags_ExpectedPublicKey(t *testing.T) {
	cmd := NewStartCmd()
	require.NoError(t, cmd.Flags().Set("expected-public-key", "cHVia2V5"))
	require.NoError(t, cmd.Flags().Set("vault-key-version", "9"))
	require.NoError(t, cmd.Flags().Set("vault-binding-mount", "claims"))

	cfg := &config.Config{}
	require.NoError(t, overlayStartFlags(cmd, cfg))
	require.Equal(t, "cHVia2V5", cfg.ExpectedPublicKey)
	require.Equal(t, 9, cfg.Backend.Vault.KeyVersion)
	require.Equal(t, "claims", cfg.Backend.Vault.BindingMount)
}

func TestOverlayStartFlags_ExplicitInsecureRaft(t *testing.T) {
	cmd := NewStartCmd()
	require.NoError(t, cmd.Flags().Set("raft-insecure", "true"))

	cfg := &config.Config{}
	require.NoError(t, overlayStartFlags(cmd, cfg))
	require.True(t, cfg.Raft.Insecure)
}

func TestOverlayStartFlags_SingleNodeBootstrap(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  string
		flag string
		want bool
	}{
		{name: "no opt-in"},
		{name: "flag enables", flag: "true", want: true},
		{name: "unset flag preserves env", env: "true", want: true},
		{name: "flag overrides env false", env: "false", flag: "true", want: true},
		{name: "flag overrides env true", env: "true", flag: "false"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.env != "" {
				t.Setenv("COSMOSIGNER_RAFT_SINGLE_NODE", tc.env)
			}
			cmd := NewStartCmd()
			args := []string{"--chain-id", "chain", "--node", "node:5555", "--key-file", "/key.json", "--raft-bootstrap", "--raft-insecure"}
			if tc.flag != "" {
				args = append(args, "--raft-single-node="+tc.flag)
			}
			require.NoError(t, cmd.ParseFlags(args))
			_, err := config.Load("", func(c *config.Config) error { return overlayStartFlags(cmd, c) })
			if tc.want {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, "raft.single_node")
			}
		})
	}
}

func TestWriteInsecureRaftWarning(t *testing.T) {
	var out bytes.Buffer
	writeInsecureRaftWarning(&out, true)
	require.Contains(t, out.String(), "WARNING: raft transport is insecure")

	out.Reset()
	writeInsecureRaftWarning(&out, false)
	require.Empty(t, out.String())
}

func TestVerifyExpectedPublicKey(t *testing.T) {
	priv := ed25519.GenPrivKey()
	be := backend.NewSoftwareFromPriv(priv)
	expected := base64.StdEncoding.EncodeToString(priv.PubKey().Bytes())

	require.NoError(t, verifyExpectedPublicKey(be, expected))
}

func TestVerifyExpectedPublicKeyMismatchFailsClosed(t *testing.T) {
	be := backend.NewSoftwareFromPriv(ed25519.GenPrivKey())
	different := ed25519.GenPrivKey().PubKey().Bytes()

	err := verifyExpectedPublicKey(be, base64.StdEncoding.EncodeToString(different))
	require.ErrorContains(t, err, "does not match")
}

func TestVerifyExpectedPublicKeyRejectsMalformedValue(t *testing.T) {
	be := backend.NewSoftwareFromPriv(ed25519.GenPrivKey())

	err := verifyExpectedPublicKey(be, "not-base64")
	require.ErrorContains(t, err, "expected public key")
}

type startupTestBackend struct {
	pub          crypto.PubKey
	binding      string
	bindingErr   error
	bindingReads int
	preflights   int
	renewals     int
	preflight    func(context.Context) error
}

func (b *startupTestBackend) PubKey() (crypto.PubKey, error) { return b.pub, nil }
func (b *startupTestBackend) Sign([]byte) ([]byte, error)    { return nil, nil }
func (b *startupTestBackend) ClusterBinding(context.Context) (string, error) {
	b.bindingReads++
	return b.binding, b.bindingErr
}
func (b *startupTestBackend) ClaimCluster(context.Context, string) error { return nil }
func (b *startupTestBackend) VerifyCanSign(ctx context.Context) error {
	b.preflights++
	if b.preflight != nil {
		return b.preflight(ctx)
	}
	return nil
}
func (b *startupTestBackend) StartRenewal() error {
	b.renewals++
	return nil
}
func (b *startupTestBackend) Close() error { return nil }

type startupTestStore struct {
	clusterID string
	ensureErr error
}

func (s *startupTestStore) EnsureClusterID(context.Context) (string, error) {
	return s.clusterID, s.ensureErr
}
func (s *startupTestStore) Reserve(string, int64, int32, int8, []byte, time.Time) (state.ReserveResult, error) {
	return state.ReserveResult{}, errors.New("unexpected reserve")
}
func (s *startupTestStore) Commit(string, int64, int32, int8, []byte, []byte) error {
	return errors.New("unexpected commit")
}
func (s *startupTestStore) Get(string) (*state.SignState, error) { return nil, state.ErrNoState }
func (s *startupTestStore) IsLeader() bool                       { return false }
func (s *startupTestStore) LeaderCh() <-chan bool                { return nil }
func (s *startupTestStore) Close() error                         { return nil }

func TestPrepareStartupRefusesBindingBeforePreflight(t *testing.T) {
	be := &startupTestBackend{
		pub:        ed25519.GenPrivKey().PubKey(),
		bindingErr: backend.ErrBindingUnclaimed,
	}
	store := &startupTestStore{clusterID: startTestClusterID}

	_, err := prepareStartup(t.Context(), be, store, false)
	require.ErrorIs(t, err, backend.ErrBindingUnclaimed)
	require.ErrorContains(t, err, startTestClusterID)
	require.Equal(t, 1, be.bindingReads)
	require.Zero(t, be.preflights)
	require.Zero(t, be.renewals)
}

func TestPrepareStartupActivatesRenewalAfterBindingAndPreflight(t *testing.T) {
	be := &startupTestBackend{pub: ed25519.GenPrivKey().PubKey(), binding: startTestClusterID}
	store := &startupTestStore{clusterID: startTestClusterID}

	id, err := prepareStartup(t.Context(), be, store, false)
	require.NoError(t, err)
	require.Equal(t, startTestClusterID, id)
	require.Equal(t, 1, be.bindingReads)
	require.Equal(t, 1, be.preflights)
	require.Equal(t, 1, be.renewals)
}

func TestPrepareStartupCancellationInterruptsBlockedPreflight(t *testing.T) {
	started := make(chan struct{})
	be := &startupTestBackend{
		pub:     ed25519.GenPrivKey().PubKey(),
		binding: startTestClusterID,
		preflight: func(ctx context.Context) error {
			close(started)
			<-ctx.Done()
			return ctx.Err()
		},
	}
	store := &startupTestStore{clusterID: startTestClusterID}
	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() {
		_, err := prepareStartup(ctx, be, store, false)
		result <- err
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("preflight did not start")
	}
	cancel()
	select {
	case err := <-result:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("startup did not stop after cancellation")
	}
	require.Equal(t, 1, be.bindingReads)
	require.Equal(t, 1, be.preflights)
	require.Zero(t, be.renewals)
}

func TestPrepareStartupChecksCancellationBeforeRenewal(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	be := &startupTestBackend{
		pub:     ed25519.GenPrivKey().PubKey(),
		binding: startTestClusterID,
		preflight: func(context.Context) error {
			cancel()
			return nil
		},
	}
	store := &startupTestStore{clusterID: startTestClusterID}

	_, err := prepareStartup(ctx, be, store, false)
	require.ErrorIs(t, err, context.Canceled)
	require.Zero(t, be.renewals)
}

func TestPrepareStartupInitializeOnlyDoesNotReadOrSign(t *testing.T) {
	be := &startupTestBackend{pub: ed25519.GenPrivKey().PubKey(), bindingErr: errors.New("must not read")}
	store := &startupTestStore{clusterID: startTestClusterID}

	id, err := prepareStartup(t.Context(), be, store, true)
	require.NoError(t, err)
	require.Equal(t, startTestClusterID, id)
	require.Zero(t, be.bindingReads)
	require.Zero(t, be.preflights)
	require.Zero(t, be.renewals)
}

func TestRunStartInitializeOnlyCreatesIdentityWithoutClaimOrConnections(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "priv_validator_key.json")
	pv := privval.GenFilePV(keyFile, filepath.Join(dir, "priv_validator_state.json"))
	pv.Key.Save()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	raftAddr := listener.Addr().String()
	require.NoError(t, listener.Close())
	cfg := config.Defaults()
	cfg.ChainID = "chain"
	cfg.NodeAddrs = []string{"127.0.0.1:1"}
	cfg.ConnKey = filepath.Join(dir, "conn_key.json")
	cfg.Backend.SoftwareKeyFile = keyFile
	cfg.Raft.NodeID = "node-1"
	cfg.Raft.BindAddr = raftAddr
	cfg.Raft.Advertise = raftAddr
	cfg.Raft.DataDir = filepath.Join(dir, "raft")
	cfg.Raft.Bootstrap = true
	cfg.Raft.SingleNode = true
	cfg.Raft.Insecure = true
	var out bytes.Buffer

	require.NoError(t, runStartMode(cfg, true, &out))
	require.NoError(t, clusterid.Validate(strings.TrimSpace(out.String())))
	require.NoFileExists(t, keyFile+".cosmosigner-cluster.json")
	require.NoFileExists(t, cfg.ConnKey)
}

type synchronizedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *synchronizedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *synchronizedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func startTestAddresses(t *testing.T, count int) []string {
	t.Helper()
	listeners := make([]net.Listener, count)
	addresses := make([]string, count)
	for i := range count {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		listeners[i] = listener
		addresses[i] = listener.Addr().String()
	}
	for _, listener := range listeners {
		require.NoError(t, listener.Close())
	}
	return addresses
}

func TestRunStartInitializeOnlyMultiNodeWaitsForCancellation(t *testing.T) {
	if testing.Short() {
		t.Skip("multi-node Raft lifecycle test")
	}
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "priv_validator_key.json")
	pv := privval.GenFilePV(keyFile, filepath.Join(dir, "priv_validator_state.json"))
	pv.Key.Save()
	addresses := startTestAddresses(t, 3)
	members := make([]config.Member, 3)
	for i := range members {
		members[i] = config.Member{ID: fmt.Sprintf("node-%d", i), Address: addresses[i]}
	}

	outputs := make([]synchronizedBuffer, 3)
	results := make([]chan error, 3)
	cancels := make([]context.CancelFunc, 3)
	for i := range results {
		cfg := config.Defaults()
		cfg.Backend.SoftwareKeyFile = keyFile
		cfg.Raft.NodeID = members[i].ID
		cfg.Raft.BindAddr = addresses[i]
		cfg.Raft.Advertise = addresses[i]
		cfg.Raft.DataDir = filepath.Join(dir, members[i].ID)
		cfg.Raft.Bootstrap = i == 0
		cfg.Raft.Insecure = true
		cfg.Raft.Members = members
		ctx, cancel := context.WithCancel(t.Context())
		cancels[i] = cancel
		t.Cleanup(cancel)
		results[i] = make(chan error, 1)
		go func() {
			results[i] <- runStartModeContext(ctx, cfg, true, &outputs[i])
		}()
	}

	var clusterID string
	require.Eventually(t, func() bool {
		for i := range outputs {
			id := strings.TrimSpace(outputs[i].String())
			if clusterid.Validate(id) != nil {
				return false
			}
			if clusterID == "" {
				clusterID = id
			}
			if id != clusterID {
				return false
			}
		}
		return true
	}, 20*time.Second, 50*time.Millisecond, "all initialize-only replicas must print one cluster ID")

	for i := range results {
		select {
		case err := <-results[i]:
			t.Fatalf("replica %d exited before cancellation: %v", i, err)
		default:
		}
	}
	for _, cancel := range cancels {
		cancel()
	}
	for i := range results {
		select {
		case err := <-results[i]:
			require.NoError(t, err, "replica %d did not shut down cleanly", i)
		case <-time.After(5 * time.Second):
			t.Fatalf("replica %d did not stop after cancellation", i)
		}
	}

	restartOutputs := make([]synchronizedBuffer, 3)
	restartResults := make([]chan error, 3)
	restartCancels := make([]context.CancelFunc, 3)
	for i := range restartResults {
		cfg := config.Defaults()
		cfg.Backend.SoftwareKeyFile = keyFile
		cfg.Raft.NodeID = members[i].ID
		cfg.Raft.BindAddr = addresses[i]
		cfg.Raft.Advertise = addresses[i]
		cfg.Raft.DataDir = filepath.Join(dir, members[i].ID)
		cfg.Raft.Insecure = true
		ctx, cancel := context.WithCancel(t.Context())
		restartCancels[i] = cancel
		t.Cleanup(cancel)
		restartResults[i] = make(chan error, 1)
		go func() {
			restartResults[i] <- runStartModeContext(ctx, cfg, true, &restartOutputs[i])
		}()
	}

	require.Eventually(t, func() bool {
		for i := range restartOutputs {
			if strings.TrimSpace(restartOutputs[i].String()) != clusterID {
				return false
			}
		}
		return true
	}, 20*time.Second, 50*time.Millisecond, "restarted replicas must load the persisted cluster ID")
	for i := range restartResults {
		select {
		case err := <-restartResults[i]:
			t.Fatalf("restarted replica %d exited before cancellation with omitted member flags: %v", i, err)
		default:
		}
	}
	for _, cancel := range restartCancels {
		cancel()
	}
	for i := range restartResults {
		select {
		case err := <-restartResults[i]:
			require.NoError(t, err, "restarted replica %d did not shut down cleanly", i)
		case <-time.After(5 * time.Second):
			t.Fatalf("restarted replica %d did not stop after cancellation", i)
		}
	}
}

type startupCountingBackend struct {
	backend.KeyBackend
	preflights atomic.Int32
	signs      atomic.Int32
}

func (b *startupCountingBackend) Sign(message []byte) ([]byte, error) {
	b.signs.Add(1)
	return b.KeyBackend.Sign(message)
}

func (b *startupCountingBackend) VerifyCanSign(ctx context.Context) error {
	b.preflights.Add(1)
	if err := ctx.Err(); err != nil {
		return err
	}
	_, err := b.Sign([]byte("startup preflight; not consensus sign bytes"))
	return err
}

func TestPrepareStartupPersistedHistoriesEnforceBindingBeforePreflight(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "priv_validator_key.json")
	pv := privval.GenFilePV(keyFile, filepath.Join(dir, "priv_validator_state.json"))
	pv.Key.Save()
	newHistory := func(name string) (state.RaftConfig, string) {
		cfg := state.RaftConfig{
			NodeID: name, BindAddr: "127.0.0.1:0", DataDir: filepath.Join(dir, name),
			Bootstrap: true, SingleNode: true, Insecure: true,
		}
		store, err := state.NewRaftStore(cfg, nil)
		require.NoError(t, err)
		require.Eventually(t, store.IsLeader, 10*time.Second, 50*time.Millisecond)
		be, err := backend.NewSoftware(keyFile)
		require.NoError(t, err)
		id, err := prepareStartup(t.Context(), be, store, true)
		require.NoError(t, err)
		require.NoError(t, be.Close())
		require.NoError(t, store.Close())
		return cfg, id
	}

	cfgA, idA := newHistory("cluster-a")
	cfgB, idB := newHistory("cluster-b")
	require.NotEqual(t, idA, idB)
	owner, err := backend.NewSoftware(keyFile)
	require.NoError(t, err)
	require.NoError(t, owner.ClaimCluster(t.Context(), idA))
	require.NoError(t, owner.Close())

	restartAndPrepare := func(cfg state.RaftConfig) (*startupCountingBackend, error) {
		store, err := state.NewRaftStore(cfg, nil)
		require.NoError(t, err)
		require.Eventually(t, store.IsLeader, 10*time.Second, 50*time.Millisecond)
		t.Cleanup(func() { require.NoError(t, store.Close()) })
		software, err := backend.NewSoftware(keyFile)
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, software.Close()) })
		counted := &startupCountingBackend{KeyBackend: software}
		_, err = prepareStartup(t.Context(), counted, store, false)
		return counted, err
	}

	accepted, err := restartAndPrepare(cfgA)
	require.NoError(t, err)
	require.Equal(t, int32(1), accepted.preflights.Load())
	require.Equal(t, int32(1), accepted.signs.Load())

	rejected, err := restartAndPrepare(cfgB)
	require.ErrorIs(t, err, backend.ErrBindingMismatch)
	require.Zero(t, rejected.preflights.Load())
	require.Zero(t, rejected.signs.Load())
}

func TestRunStartUnclaimedKeyFailsBeforeCreatingNodeIdentity(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "priv_validator_key.json")
	pv := privval.GenFilePV(keyFile, filepath.Join(dir, "priv_validator_state.json"))
	pv.Key.Save()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	raftAddr := listener.Addr().String()
	require.NoError(t, listener.Close())
	cfg := config.Defaults()
	cfg.ChainID = "chain"
	cfg.NodeAddrs = []string{"127.0.0.1:1"}
	cfg.ConnKey = filepath.Join(dir, "conn_key.json")
	cfg.Backend.SoftwareKeyFile = keyFile
	cfg.Raft.NodeID = "node-1"
	cfg.Raft.BindAddr = raftAddr
	cfg.Raft.Advertise = raftAddr
	cfg.Raft.DataDir = filepath.Join(dir, "raft")
	cfg.Raft.Bootstrap = true
	cfg.Raft.SingleNode = true
	cfg.Raft.Insecure = true

	err = runStartMode(cfg, false, &bytes.Buffer{})
	require.ErrorIs(t, err, backend.ErrBindingUnclaimed)
	require.Contains(t, err.Error(), "cluster")
	require.NoFileExists(t, cfg.ConnKey)
}

func TestStartCommandExposesInitializeOnlyMode(t *testing.T) {
	cmd := NewStartCmd()
	flag := cmd.Flags().Lookup("initialize-only")
	require.NotNil(t, flag)
	require.Contains(t, flag.Usage, "quorum")
}
