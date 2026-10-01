package backend

import (
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func testProvisionConfig() GCPProvisionConfig {
	return GCPProvisionConfig{
		Project: "p", Location: "global", KeyRing: "r", Key: "validator",
		Protection: kmspb.ProtectionLevel_SOFTWARE,
	}
}

func TestGCPProvisionExistingRingCreatesOnlyKey(t *testing.T) {
	client := &fakeImportClient{
		ring: &kmspb.KeyRing{Name: testImportRing},
		errs: map[string]error{"CreateKeyRing": status.Error(codes.PermissionDenied, "denied")},
	}
	cfg := testProvisionConfig()
	cfg.Protection = kmspb.ProtectionLevel_HSM

	name, err := gcpProvisionKey(t.Context(), client, cfg)
	require.NoError(t, err)
	require.Equal(t, testImportKey, name)
	require.Equal(t, []string{"GetKeyRing", "CreateCryptoKey"}, client.calls)
	require.Equal(t, kmspb.CryptoKey_ASYMMETRIC_SIGN, client.key.Purpose)
	require.Equal(t, kmspb.CryptoKeyVersion_EC_SIGN_ED25519, client.key.VersionTemplate.Algorithm)
	require.Equal(t, kmspb.ProtectionLevel_HSM, client.key.VersionTemplate.ProtectionLevel)
}

func TestGCPProvisionCreatesMissingRing(t *testing.T) {
	client := &fakeImportClient{}

	name, err := gcpProvisionKey(t.Context(), client, testProvisionConfig())
	require.NoError(t, err)
	require.Equal(t, testImportKey, name)
	require.Equal(t, testImportRing, client.ring.Name)
	require.Equal(t, []string{"GetKeyRing", "CreateKeyRing", "CreateCryptoKey"}, client.calls)
}

func TestGCPProvisionDoesNotCreateOnDeniedRingRead(t *testing.T) {
	client := &fakeImportClient{errs: map[string]error{
		"GetKeyRing": status.Error(codes.PermissionDenied, "denied"),
	}}

	_, err := gcpProvisionKey(t.Context(), client, testProvisionConfig())
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	require.Equal(t, []string{"GetKeyRing"}, client.calls)
}

func TestGCPProvisionRefusesExistingKey(t *testing.T) {
	client := &fakeImportClient{ring: &kmspb.KeyRing{Name: testImportRing}, key: importableKey()}

	_, err := gcpProvisionKey(t.Context(), client, testProvisionConfig())
	require.Equal(t, codes.AlreadyExists, status.Code(err))
}
