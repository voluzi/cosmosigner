package backend

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/privval"
	"github.com/stretchr/testify/require"
)

const (
	clusterA = "3b12f1df-5232-4804-897e-917bf397618a"
	clusterB = "0f6f0173-538d-4f07-a85e-9c4af5523c4d"
)

func newSoftwareKeyFile(t *testing.T, dir string) string {
	t.Helper()
	keyFile := filepath.Join(dir, "priv_validator_key.json")
	pv := privval.GenFilePV(keyFile, filepath.Join(dir, "priv_validator_state.json"))
	pv.Key.Save()
	return keyFile
}

func TestSoftwareBindingClaimAndRead(t *testing.T) {
	keyFile := newSoftwareKeyFile(t, t.TempDir())
	be, err := NewSoftware(keyFile)
	require.NoError(t, err)

	_, err = be.ClusterBinding(t.Context())
	require.ErrorIs(t, err, ErrBindingUnclaimed)
	require.NoError(t, be.ClaimCluster(t.Context(), clusterA))
	require.NoError(t, be.ClaimCluster(t.Context(), clusterA), "same-owner retry must be idempotent")
	got, err := be.ClusterBinding(t.Context())
	require.NoError(t, err)
	require.Equal(t, clusterA, got)

	info, err := os.Stat(be.bindingPath)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	err = be.ClaimCluster(t.Context(), clusterB)
	require.ErrorIs(t, err, ErrBindingMismatch)
}

func TestSoftwareBindingConcurrentClaimsChooseOneOwner(t *testing.T) {
	keyFile := newSoftwareKeyFile(t, t.TempDir())
	be, err := NewSoftware(keyFile)
	require.NoError(t, err)
	realLink := be.bindingOps.link
	linkReady := make(chan struct{}, 2)
	releaseLinks := make(chan struct{})
	be.bindingOps.link = func(oldPath, newPath string) error {
		linkReady <- struct{}{}
		<-releaseLinks
		return realLink(oldPath, newPath)
	}

	ids := []string{clusterA, clusterB}
	errs := make([]error, len(ids))
	var wg sync.WaitGroup
	for i, id := range ids {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = be.ClaimCluster(context.Background(), id)
		}()
	}
	for range ids {
		select {
		case <-linkReady:
		case <-time.After(2 * time.Second):
			t.Fatal("claimant did not reach atomic publication")
		}
	}
	close(releaseLinks)
	wg.Wait()

	successes := 0
	winner := ""
	for i, err := range errs {
		if err == nil {
			successes++
			winner = ids[i]
			continue
		}
		require.ErrorIs(t, err, ErrBindingMismatch)
	}
	require.Equal(t, 1, successes)
	owner, err := be.ClusterBinding(t.Context())
	require.NoError(t, err)
	require.Equal(t, winner, owner)
}

func TestSoftwareBindingRetryReestablishesDurabilityAfterDirectorySyncFailure(t *testing.T) {
	keyFile := newSoftwareKeyFile(t, t.TempDir())
	be, err := NewSoftware(keyFile)
	require.NoError(t, err)
	realSync := be.bindingOps.sync
	directorySyncs := 0
	markerSyncs := 0
	be.bindingOps.sync = func(file *os.File) error {
		info, statErr := file.Stat()
		require.NoError(t, statErr)
		if info.IsDir() {
			directorySyncs++
			if directorySyncs == 1 {
				return errors.New("injected directory sync failure")
			}
		} else if file.Name() == be.bindingPath {
			markerSyncs++
		}
		return realSync(file)
	}

	err = be.ClaimCluster(t.Context(), clusterA)
	require.ErrorContains(t, err, "injected directory sync failure")
	owner, err := be.ClusterBinding(t.Context())
	require.NoError(t, err)
	require.Equal(t, clusterA, owner, "published marker must remain complete after a directory sync failure")

	require.NoError(t, be.ClaimCluster(t.Context(), clusterA))
	require.Equal(t, 2, directorySyncs)
	require.Equal(t, 1, markerSyncs, "same-owner retry must sync the published marker")
}

func TestSoftwareBindingSymlinkAliasesShareMarker(t *testing.T) {
	dir := t.TempDir()
	keyFile := newSoftwareKeyFile(t, dir)
	alias := filepath.Join(dir, "validator-key-link.json")
	require.NoError(t, os.Symlink(keyFile, alias))

	direct, err := NewSoftware(keyFile)
	require.NoError(t, err)
	throughAlias, err := NewSoftware(alias)
	require.NoError(t, err)
	require.Equal(t, direct.bindingPath, throughAlias.bindingPath)
	require.NoError(t, direct.ClaimCluster(t.Context(), clusterA))
	owner, err := throughAlias.ClusterBinding(t.Context())
	require.NoError(t, err)
	require.Equal(t, clusterA, owner)
}

func TestSoftwareBindingRejectsCorruptOrReplacedKey(t *testing.T) {
	dir := t.TempDir()
	keyFile := newSoftwareKeyFile(t, dir)
	be, err := NewSoftware(keyFile)
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(be.bindingPath, []byte("{\"version\":1"), 0o600))
	_, err = be.ClusterBinding(t.Context())
	require.ErrorIs(t, err, ErrBindingCorrupt)
	require.ErrorIs(t, be.ClaimCluster(t.Context(), clusterA), ErrBindingCorrupt)

	record := softwareBindingRecord{Version: 1, ClusterID: clusterA, PublicKey: "wrong"}
	data, err := json.Marshal(record)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(be.bindingPath, data, 0o600))
	_, err = be.ClusterBinding(t.Context())
	require.ErrorIs(t, err, ErrBindingCorrupt)
}

func TestSoftwareBindingRejectsKeyFileReplacement(t *testing.T) {
	dir := t.TempDir()
	keyFile := newSoftwareKeyFile(t, dir)
	be, err := NewSoftware(keyFile)
	require.NoError(t, err)
	require.NoError(t, be.ClaimCluster(t.Context(), clusterA))

	replacementDir := t.TempDir()
	replacement := newSoftwareKeyFile(t, replacementDir)
	data, err := os.ReadFile(replacement)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(keyFile, data, 0o600))
	reloaded, err := NewSoftware(keyFile)
	require.NoError(t, err)
	_, err = reloaded.ClusterBinding(t.Context())
	require.ErrorIs(t, err, ErrBindingCorrupt)
}

func TestInMemorySoftwareBindingIsUnsupported(t *testing.T) {
	be := NewSoftwareFromPriv(ed25519.GenPrivKey())
	_, err := be.ClusterBinding(t.Context())
	require.ErrorIs(t, err, ErrBindingUnsupported)
	require.ErrorIs(t, be.ClaimCluster(t.Context(), clusterA), ErrBindingUnsupported)
}

func TestRequireClusterBindingFailsClosed(t *testing.T) {
	keyFile := newSoftwareKeyFile(t, t.TempDir())
	be, err := NewSoftware(keyFile)
	require.NoError(t, err)

	err = RequireClusterBinding(t.Context(), be, clusterA)
	require.ErrorIs(t, err, ErrBindingUnclaimed)
	require.ErrorContains(t, err, clusterA)
	require.NoError(t, be.ClaimCluster(t.Context(), clusterA))
	require.NoError(t, RequireClusterBinding(t.Context(), be, clusterA))

	err = RequireClusterBinding(t.Context(), be, clusterB)
	require.True(t, errors.Is(err, ErrBindingMismatch))
	require.ErrorContains(t, err, clusterA)
	require.ErrorContains(t, err, clusterB)
}
