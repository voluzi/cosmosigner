package backend

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/cometbft/cometbft/crypto/ed25519"
	cmtjson "github.com/cometbft/cometbft/libs/json"
	"github.com/cometbft/cometbft/privval"
	"github.com/stretchr/testify/require"
)

func TestSoftwareClaimAndProvisionSerializeClaimFirst(t *testing.T) {
	requireSoftwareFileSafetySupport(t)
	keyFile := newSoftwareKeyFile(t, t.TempDir())
	be, err := NewSoftware(keyFile)
	require.NoError(t, err)
	claimLocked := make(chan struct{})
	releaseClaim := make(chan struct{})
	be.operationHooks.afterLock = func() {
		close(claimLocked)
		<-releaseClaim
	}

	claimResult := make(chan error, 1)
	go func() { claimResult <- be.ClaimCluster(t.Context(), clusterA) }()
	<-claimLocked
	provisionResult := make(chan error, 1)
	go func() {
		_, provisionErr := ProvisionSoftwareKey(t.Context(), keyFile, true)
		provisionResult <- provisionErr
	}()
	requireStillWaiting(t, provisionResult)

	close(releaseClaim)
	require.NoError(t, <-claimResult)
	require.ErrorContains(t, <-provisionResult, "binding marker")
	owner, err := be.ClusterBinding(t.Context())
	require.NoError(t, err)
	require.Equal(t, clusterA, owner)
}

func TestSoftwareClaimAndProvisionSerializeProvisionFirst(t *testing.T) {
	requireSoftwareFileSafetySupport(t)
	keyFile := newSoftwareKeyFile(t, t.TempDir())
	be, err := NewSoftware(keyFile)
	require.NoError(t, err)
	provisionLocked := make(chan struct{})
	releaseProvision := make(chan struct{})

	provisionResult := make(chan error, 1)
	go func() {
		_, provisionErr := provisionSoftwareKey(t.Context(), keyFile, true, softwareOperationHooks{
			afterLock: func() {
				close(provisionLocked)
				<-releaseProvision
			},
		})
		provisionResult <- provisionErr
	}()
	<-provisionLocked
	claimResult := make(chan error, 1)
	go func() { claimResult <- be.ClaimCluster(t.Context(), clusterA) }()
	requireStillWaiting(t, claimResult)

	close(releaseProvision)
	require.NoError(t, <-provisionResult)
	require.ErrorContains(t, <-claimResult, "changed")
	require.NoFileExists(t, be.bindingPath)
}

func TestSoftwareLockWaitHonorsContextCancellation(t *testing.T) {
	requireSoftwareFileSafetySupport(t)
	keyFile := newSoftwareKeyFile(t, t.TempDir())
	be, err := NewSoftware(keyFile)
	require.NoError(t, err)
	unlock, err := acquireSoftwareKeyLock(context.Background(), be.keyPath)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, unlock()) })

	ctx, cancel := context.WithCancel(context.Background())
	claimResult := make(chan error, 1)
	go func() { claimResult <- be.ClaimCluster(ctx, clusterA) }()
	requireStillWaiting(t, claimResult)
	cancel()
	require.ErrorIs(t, <-claimResult, context.Canceled)
	require.NoFileExists(t, be.bindingPath)
}

func TestNewSoftwareRejectsMultiplyLinkedKey(t *testing.T) {
	requireSoftwareFileSafetySupport(t)
	dir := t.TempDir()
	keyFile := newSoftwareKeyFile(t, dir)
	alias := filepath.Join(dir, "key-alias.json")
	require.NoError(t, os.Link(keyFile, alias))

	_, err := NewSoftware(alias)
	require.ErrorContains(t, err, "multiple hard links")
}

func TestNewSoftwareRejectsMismatchedDeclaredPublicKey(t *testing.T) {
	requireSoftwareFileSafetySupport(t)
	keyFile := newSoftwareKeyFile(t, t.TempDir())
	data, err := os.ReadFile(keyFile)
	require.NoError(t, err)
	var pvKey privval.FilePVKey
	require.NoError(t, cmtjson.Unmarshal(data, &pvKey))
	pvKey.PubKey = ed25519.GenPrivKey().PubKey()
	data, err = cmtjson.MarshalIndent(pvKey, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(keyFile, data, 0o600))

	_, err = NewSoftware(keyFile)
	require.ErrorContains(t, err, "pub_key does not match priv_key")
}

func TestProvisionSoftwareKeyRejectsDanglingLeafSymlink(t *testing.T) {
	dir := t.TempDir()
	alias := filepath.Join(dir, "key-link.json")
	require.NoError(t, os.Symlink(filepath.Join(dir, "missing-key.json"), alias))

	_, err := ProvisionSoftwareKey(t.Context(), alias, true)
	require.ErrorContains(t, err, "resolve")
	info, statErr := os.Lstat(alias)
	require.NoError(t, statErr)
	require.NotZero(t, info.Mode()&os.ModeSymlink)
}

func requireStillWaiting(t *testing.T, result <-chan error) {
	t.Helper()
	select {
	case err := <-result:
		t.Fatalf("operation returned before the key lock was released: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
}

func requireSoftwareFileSafetySupport(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("software key locking and link-count checks are supported on Linux and macOS")
	}
}
