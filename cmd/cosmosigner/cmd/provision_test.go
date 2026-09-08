package cmd

import (
	"os"
	"path/filepath"
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

	err := provisionSoftware(target, true)

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

	err := provisionSoftware(alias, true)

	require.ErrorContains(t, err, "binding marker")
	got, readErr := os.ReadFile(target)
	require.NoError(t, readErr)
	require.Equal(t, want, got, "canonical key target must remain unchanged")
}

func TestProvisionSoftwareOverwriteAllowsUnclaimedKey(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "priv_validator_key.json")
	before := writeProvisionTestKey(t, keyFile)

	require.NoError(t, provisionSoftware(keyFile, true))
	after, err := os.ReadFile(keyFile)
	require.NoError(t, err)
	require.NotEqual(t, before, after)
}
