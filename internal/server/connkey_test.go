package server

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadOrGenConnKey_RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys", "conn_key.json")

	// First call generates and persists.
	k1, err := LoadOrGenConnKey(path)
	require.NoError(t, err)
	require.NotNil(t, k1)

	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	// Second call must load the SAME key — a silently regenerated key would
	// change the signer's SecretConnection identity across restarts.
	k2, err := LoadOrGenConnKey(path)
	require.NoError(t, err)
	require.Equal(t, k1.Bytes(), k2.Bytes())
	require.True(t, k1.PubKey().Equals(k2.PubKey()))
}

func TestLoadOrGenConnKey_CorruptFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "conn_key.json")
	require.NoError(t, os.WriteFile(path, []byte("not-json"), 0o600))
	_, err := LoadOrGenConnKey(path)
	require.Error(t, err, "corrupt key file must fail loudly, not silently regenerate")
}
