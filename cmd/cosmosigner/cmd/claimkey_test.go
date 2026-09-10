package cmd

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/cometbft/cometbft/privval"
	"github.com/stretchr/testify/require"
)

func TestClaimKeyRejectsInvalidClusterIDBeforeBackendIO(t *testing.T) {
	command := NewClaimKeyCmd()
	command.SetArgs([]string{"--cluster-id", "invalid", "--key-file", filepath.Join(t.TempDir(), "missing.json")})
	err := command.Execute()
	require.ErrorContains(t, err, "canonical lowercase UUID")
	require.NotContains(t, err.Error(), "read key file")
}

func TestClaimKeyCreatesSoftwareBindingAndReportsResource(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "priv_validator_key.json")
	pv := privval.GenFilePV(keyFile, filepath.Join(dir, "priv_validator_state.json"))
	pv.Key.Save()
	var out bytes.Buffer
	command := NewClaimKeyCmd()
	command.SetOut(&out)
	command.SetArgs([]string{"--cluster-id", clusterAForClaimTest, "--key-file", keyFile})

	require.NoError(t, command.Execute())
	require.Contains(t, out.String(), clusterAForClaimTest)
	require.Contains(t, out.String(), keyFile+".cosmosigner-cluster.json")

	for _, forbidden := range []string{"force", "adopt-key", "clear"} {
		require.Nil(t, command.Flags().Lookup(forbidden))
	}
}

const clusterAForClaimTest = "3b12f1df-5232-4804-897e-917bf397618a"
