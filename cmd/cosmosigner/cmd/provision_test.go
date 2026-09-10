package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/cometbft/cometbft/privval"
	"github.com/stretchr/testify/require"
)

func writeProvisionTestKey(t *testing.T, path string) []byte {
	t.Helper()
	pv := privval.GenFilePV(path, "")
	pv.Key.Save()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return data
}

func TestProvisionSoftwareOverwriteRejectsCanonicalBindingMarker(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "priv_validator_key.json")
	want := writeProvisionTestKey(t, target)
	marker := target + ".cosmosigner-cluster.json"
	require.NoError(t, os.WriteFile(marker, []byte("claimed"), 0o600))

	err := provisionSoftware(t.Context(), target, true)

	require.ErrorContains(t, err, "binding marker")
	got, readErr := os.ReadFile(target)
	require.NoError(t, readErr)
	require.Equal(t, want, got, "claimed key material must remain unchanged")
}

func TestProvisionSoftwareOverwriteRejectsMarkerBesideSymlinkTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "priv_validator_key.json")
	want := writeProvisionTestKey(t, target)
	alias := filepath.Join(dir, "validator-key-link.json")
	require.NoError(t, os.Symlink(target, alias))
	require.NoError(t, os.WriteFile(target+".cosmosigner-cluster.json", []byte("claimed"), 0o600))

	err := provisionSoftware(t.Context(), alias, true)

	require.ErrorContains(t, err, "binding marker")
	got, readErr := os.ReadFile(target)
	require.NoError(t, readErr)
	require.Equal(t, want, got, "canonical key target must remain unchanged")
}

func TestProvisionSoftwareOverwriteAllowsUnclaimedKey(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "priv_validator_key.json")
	before := writeProvisionTestKey(t, keyFile)

	require.NoError(t, provisionSoftware(t.Context(), keyFile, true))
	after, err := os.ReadFile(keyFile)
	require.NoError(t, err)
	require.NotEqual(t, before, after)
}

func TestProvisionSoftwareRejectsOrphanBindingMarker(t *testing.T) {
	for _, overwrite := range []bool{false, true} {
		t.Run(fmt.Sprintf("overwrite=%t", overwrite), func(t *testing.T) {
			dir := t.TempDir()
			keyFile := filepath.Join(dir, "priv_validator_key.json")
			require.NoError(t, os.WriteFile(keyFile+".cosmosigner-cluster.json", []byte("orphan"), 0o600))

			err := provisionSoftware(t.Context(), keyFile, overwrite)

			require.ErrorContains(t, err, "binding marker")
			require.NoFileExists(t, keyFile)
		})
	}
}

func TestProvisionSoftwareOverwritePreservesLeafSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "priv_validator_key.json")
	before := writeProvisionTestKey(t, target)
	alias := filepath.Join(dir, "validator-key-link.json")
	require.NoError(t, os.Symlink(target, alias))

	require.NoError(t, provisionSoftware(t.Context(), alias, true))

	info, err := os.Lstat(alias)
	require.NoError(t, err)
	require.NotZero(t, info.Mode()&os.ModeSymlink, "overwrite must preserve the leaf symlink")
	after, err := os.ReadFile(target)
	require.NoError(t, err)
	require.NotEqual(t, before, after)
}

func TestProvisionSoftwareOverwriteRejectsMultiplyLinkedKey(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("software key locking and link-count checks are supported on Linux and macOS")
	}
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "priv_validator_key.json")
	want := writeProvisionTestKey(t, keyFile)
	alias := filepath.Join(dir, "key-alias.json")
	require.NoError(t, os.Link(keyFile, alias))

	err := provisionSoftware(t.Context(), alias, true)

	require.ErrorContains(t, err, "multiple hard links")
	got, readErr := os.ReadFile(keyFile)
	require.NoError(t, readErr)
	require.Equal(t, want, got)
}
