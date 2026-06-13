package backend

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/stretchr/testify/require"
)

func TestSoftwareSignVerify(t *testing.T) {
	priv := ed25519.GenPrivKey()
	be := NewSoftwareFromPriv(priv)

	pub, err := be.PubKey()
	require.NoError(t, err)

	msg := sha256.Sum256([]byte("hello"))
	sig, err := be.Sign(msg[:])
	require.NoError(t, err)
	require.True(t, pub.VerifySignature(msg[:], sig))
}

func TestParseTransitSignature(t *testing.T) {
	raw := make([]byte, ed25519.SignatureSize)
	for i := range raw {
		raw[i] = byte(i)
	}
	good := "vault:v1:" + base64.StdEncoding.EncodeToString(raw)
	got, err := parseTransitSignature(good)
	require.NoError(t, err)
	require.Equal(t, raw, got)

	for _, bad := range []string{
		"not-a-signature",
		"vault:v1:" + base64.StdEncoding.EncodeToString([]byte("too-short")),
		"other:v1:" + base64.StdEncoding.EncodeToString(raw),
	} {
		_, err := parseTransitSignature(bad)
		require.Error(t, err, "input %q should fail", bad)
	}
}
