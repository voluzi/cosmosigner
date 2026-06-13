package backend

import (
	"crypto/ed25519"
	"crypto/x509"
	"path/filepath"
	"testing"

	"github.com/cometbft/cometbft/privval"
	"github.com/stretchr/testify/require"
)

func TestLoadKeyFilePKCS8(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "priv_validator_key.json")
	pv := privval.GenFilePV(keyFile, filepath.Join(dir, "state.json"))
	pv.Key.Save()

	der, pub, err := LoadKeyFilePKCS8(keyFile)
	require.NoError(t, err)
	require.Equal(t, pv.Key.PubKey.Bytes(), pub.Bytes())

	// The PKCS#8 DER must decode to an ed25519 key with the same identity.
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	require.NoError(t, err)
	stdPriv, ok := parsed.(ed25519.PrivateKey)
	require.True(t, ok)
	require.Equal(t, pub.Bytes(), []byte(stdPriv.Public().(ed25519.PublicKey)))

	// And produce identical signatures to the original cometbft key.
	msg := []byte("sign-bytes")
	cmtSig, err := pv.Key.PrivKey.Sign(msg)
	require.NoError(t, err)
	require.Equal(t, cmtSig, ed25519.Sign(stdPriv, msg))
}
