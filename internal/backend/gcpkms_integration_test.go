//go:build gcpkms_integration

package backend

import (
	"crypto/rand"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestGCPKMS_SignVerify exercises the real Cloud KMS backend end to end:
// fetch the public key, sign random data, and verify the signature.
//
// Run with a provisioned EC_SIGN_ED25519 key:
//
//	GCP_KMS_KEY_VERSION=projects/P/locations/L/keyRings/R/cryptoKeys/K/cryptoKeyVersions/1 \
//	GOOGLE_APPLICATION_CREDENTIALS=/path/sa.json \
//	go test -tags gcpkms_integration -run GCPKMS ./internal/backend/
func TestGCPKMS_SignVerify(t *testing.T) {
	keyVersion := os.Getenv("GCP_KMS_KEY_VERSION")
	if keyVersion == "" {
		t.Skip("set GCP_KMS_KEY_VERSION to run this test")
	}

	be, err := NewGCPKMS(GCPKMSConfig{
		KeyVersion:      keyVersion,
		CredentialsFile: os.Getenv("GCP_CREDENTIALS_FILE"), // optional; else ADC
	})
	require.NoError(t, err)
	defer be.Close()

	pub, err := be.PubKey()
	require.NoError(t, err)
	require.Len(t, pub.Bytes(), 32, "ed25519 public key must be 32 bytes")

	msg := make([]byte, 128)
	_, err = rand.Read(msg)
	require.NoError(t, err)

	sig, err := be.Sign(msg)
	require.NoError(t, err)
	require.Len(t, sig, 64, "ed25519 signature must be 64 bytes")
	require.True(t, pub.VerifySignature(msg, sig), "KMS signature must verify against the public key")
}

// TestGCPKMS_VerifyCanSign proves the startup preflight passes against a
// working, signable key. (The failure path — GetPublicKey allowed but
// AsymmetricSign denied — depends on a restricted service-account/IAM binding
// that is impractical to provision from a test.)
func TestGCPKMS_VerifyCanSign(t *testing.T) {
	keyVersion := os.Getenv("GCP_KMS_KEY_VERSION")
	if keyVersion == "" {
		t.Skip("set GCP_KMS_KEY_VERSION to run this test")
	}

	be, err := NewGCPKMS(GCPKMSConfig{
		KeyVersion:      keyVersion,
		CredentialsFile: os.Getenv("GCP_CREDENTIALS_FILE"), // optional; else ADC
	})
	require.NoError(t, err)
	defer be.Close()

	require.NoError(t, be.VerifyCanSign())
}
