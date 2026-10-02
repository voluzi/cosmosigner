//go:build awskms_integration

package backend

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/stretchr/testify/require"
)

func TestAWSKMSIntegrationSignDeterminism(t *testing.T) {
	keyID := os.Getenv("AWS_KMS_KEY_ID")
	if keyID == "" {
		t.Skip("set AWS_KMS_KEY_ID to a dedicated single-Region Ed25519 test key")
	}
	cfg := AWSKMSConfig{KeyID: keyID}
	first, err := NewAWSKMS(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, first.Close()) })
	second, err := NewAWSKMS(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, second.Close()) })
	requireSignDeterminism(t, first, second)
	require.NoError(t, first.VerifyCanSign(t.Context()))
}

// This drill creates a billable key and schedules its deletion after the test, even on failure.
func TestAWSKMSIntegrationImportRoundTrip(t *testing.T) {
	if os.Getenv("AWS_KMS_IMPORT_TEST") != "1" {
		t.Skip("set AWS_KMS_IMPORT_TEST=1 to create and import a billable test key")
	}
	cfg := AWSKMSConfig{Timeout: 30 * time.Second}
	client, err := newAWSClient(t.Context(), cfg)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), cfg.Timeout)
	defer cancel()
	keyARN, err := createAWSKey(ctx, client, types.OriginTypeExternal)
	if keyARN != "" {
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			_, err := client.ScheduleKeyDeletion(ctx, &kms.ScheduleKeyDeletionInput{KeyId: aws.String(keyARN), PendingWindowInDays: aws.Int32(7)})
			require.NoError(t, err, "schedule deletion of AWS test key %s", keyARN)
		})
	}
	require.NoError(t, err)
	_, source, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(source)
	require.NoError(t, err)
	cfg.KeyID = keyARN
	imported, ready, err := AWSImportKey(t.Context(), cfg, der)
	require.NoError(t, err)
	require.True(t, ready, "AWS import still finalizing for %s; verify manually before deployment", keyARN)
	require.Equal(t, keyARN, imported)
	first, err := NewAWSKMS(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, first.Close()) })
	second, err := NewAWSKMS(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, second.Close()) })
	requireSignDeterminism(t, first, second)
	message := []byte(determinismTestMessage)
	signature, err := first.Sign(message)
	require.NoError(t, err)
	require.Equal(t, ed25519.Sign(source, message), signature)
	require.NoError(t, first.VerifyCanSign(t.Context()))
}
