package backend

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

// A relocated marker lets a key mounted read-only (a Kubernetes Secret) be claimed: the marker and
// its lock live in a writable directory, and nothing is written next to the key.
func TestSoftwareBindingFileRelocatesMarkerAndLock(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs POSIX permissions enforced for a non-root user")
	}
	keyDir := t.TempDir()
	keyFile := newSoftwareKeyFile(t, keyDir)
	require.NoError(t, os.Chmod(keyDir, 0o500))
	t.Cleanup(func() { _ = os.Chmod(keyDir, 0o700) })
	bindingFile := filepath.Join(t.TempDir(), "cluster.json")

	be, err := NewSoftwareWithBindingFile(keyFile, bindingFile)
	require.NoError(t, err)
	_, err = be.ClusterBinding(t.Context())
	require.ErrorIs(t, err, ErrBindingUnclaimed)
	require.NoError(t, be.ClaimCluster(t.Context(), clusterA))

	got, err := be.ClusterBinding(t.Context())
	require.NoError(t, err)
	require.Equal(t, clusterA, got)
	require.FileExists(t, bindingFile)
	require.FileExists(t, bindingFile+softwareLockSuffix)
	entries, err := os.ReadDir(keyDir)
	require.NoError(t, err)
	for _, entry := range entries {
		require.NotContains(t, entry.Name(), "cosmosigner-cluster", "nothing may be written next to the key")
	}

	// A fresh backend over the same files reads the same owner and refuses another cluster.
	again, err := NewSoftwareWithBindingFile(keyFile, bindingFile)
	require.NoError(t, err)
	require.ErrorIs(t, again.ClaimCluster(t.Context(), clusterB), ErrBindingMismatch)
}

// The marker records the key's public key, so a relocated marker cannot be adopted by other key
// material pointed at the same path.
func TestSoftwareBindingFileRejectsMarkerOfAnotherKey(t *testing.T) {
	bindingFile := filepath.Join(t.TempDir(), "cluster.json")
	first, err := NewSoftwareWithBindingFile(newSoftwareKeyFile(t, t.TempDir()), bindingFile)
	require.NoError(t, err)
	require.NoError(t, first.ClaimCluster(t.Context(), clusterA))

	second, err := NewSoftwareWithBindingFile(newSoftwareKeyFile(t, t.TempDir()), bindingFile)
	require.NoError(t, err)
	_, err = second.ClusterBinding(t.Context())
	require.ErrorIs(t, err, ErrBindingCorrupt)
}

func TestSoftwareBindingFileMustDifferFromKey(t *testing.T) {
	keyFile := newSoftwareKeyFile(t, t.TempDir())
	_, err := NewSoftwareWithBindingFile(keyFile, keyFile)
	require.Error(t, err)
}

func TestClaimConfigSubstitutesOnlyConfiguredClaimCredentials(t *testing.T) {
	cfg := Config{
		Type:   TypeVault,
		Vault:  VaultConfig{TokenFile: "/runtime/token", ClaimTokenFile: "/claim/token"},
		GCPKMS: GCPKMSConfig{CredentialsFile: "/runtime/sa.json"},
	}
	claim := ClaimConfig(cfg)
	require.Equal(t, "/claim/token", claim.Vault.TokenFile)
	require.Equal(t, "/runtime/sa.json", claim.GCPKMS.CredentialsFile, "no claim credentials keeps the runtime identity")
	require.Equal(t, "/runtime/token", cfg.Vault.TokenFile, "the runtime config is not modified")
	require.True(t, HasSeparateClaimCredentials(cfg))

	cfg.Type = TypeGCPKMS
	require.False(t, HasSeparateClaimCredentials(cfg))
	cfg.GCPKMS.ClaimCredentialsFile = "/claim/sa.json"
	require.Equal(t, "/claim/sa.json", ClaimConfig(cfg).GCPKMS.CredentialsFile)
	require.True(t, HasSeparateClaimCredentials(cfg))

	require.False(t, HasSeparateClaimCredentials(Config{Type: TypeSoftware}))
}

// link(2) never follows a symlink, so a symlink at the marker path would read as unclaimed yet make
// every claim fail; refuse it up front.
func TestSoftwareBindingFileRejectsASymlink(t *testing.T) {
	keyFile := newSoftwareKeyFile(t, t.TempDir())
	dir := t.TempDir()
	dangling := filepath.Join(dir, "cluster.json")
	require.NoError(t, os.Symlink(filepath.Join(dir, "missing.json"), dangling))
	_, err := NewSoftwareWithBindingFile(keyFile, dangling)
	require.ErrorContains(t, err, "symlink")

	toKey := filepath.Join(dir, "to-key.json")
	require.NoError(t, os.Symlink(keyFile, toKey))
	_, err = NewSoftwareWithBindingFile(keyFile, toKey)
	require.ErrorContains(t, err, "symlink")
}
