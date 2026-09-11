//go:build gcpkms_integration

package backend

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestGCPKMS_SignVerify exercises the real Cloud KMS backend end to end and
// verifies deterministic signing through separate clients for the configured
// key version and protection level.
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

	cfg := GCPKMSConfig{
		KeyVersion:      keyVersion,
		CredentialsFile: os.Getenv("GCP_CREDENTIALS_FILE"), // optional; else ADC
	}
	first, err := NewGCPKMS(cfg)
	require.NoError(t, err)
	defer first.Close()

	second, err := NewGCPKMS(cfg)
	require.NoError(t, err)
	defer second.Close()

	requireSignDeterminism(t, first, second)
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

	require.NoError(t, be.VerifyCanSign(t.Context()))
}
