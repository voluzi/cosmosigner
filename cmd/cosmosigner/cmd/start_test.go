package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/voluzi/cosmosigner/internal/config"
)

func TestParseMembers_Valid(t *testing.T) {
	members, err := parseMembers([]string{"a=1.2.3.4:7070", "b=5.6.7.8:7070"})
	require.NoError(t, err)
	require.Equal(t, []config.Member{
		{ID: "a", Address: "1.2.3.4:7070"},
		{ID: "b", Address: "5.6.7.8:7070"},
	}, members)
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
