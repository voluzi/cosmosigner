package cmd

import (
	"encoding/base64"
	"testing"

	"github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/stretchr/testify/require"

	"github.com/voluzi/cosmosigner/internal/backend"
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

	cfg := &config.Config{}
	require.NoError(t, overlayStartFlags(cmd, cfg))
	require.Equal(t, "cHVia2V5", cfg.ExpectedPublicKey)
	require.Equal(t, 9, cfg.Backend.Vault.KeyVersion)
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
