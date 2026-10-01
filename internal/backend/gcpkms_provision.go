package backend

import (
	"context"
	"fmt"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/googleapis/gax-go/v2"
)

// GCPProvisionConfig configures generation of a new signing key in Cloud KMS.
type GCPProvisionConfig struct {
	Project         string
	Location        string
	KeyRing         string
	Key             string
	Protection      kmspb.ProtectionLevel
	CredentialsFile string
}

type gcpProvisionClient interface {
	GetKeyRing(context.Context, *kmspb.GetKeyRingRequest, ...gax.CallOption) (*kmspb.KeyRing, error)
	CreateKeyRing(context.Context, *kmspb.CreateKeyRingRequest, ...gax.CallOption) (*kmspb.KeyRing, error)
	CreateCryptoKey(context.Context, *kmspb.CreateCryptoKeyRequest, ...gax.CallOption) (*kmspb.CryptoKey, error)
}

// GCPProvisionKey generates an EC_SIGN_ED25519 key with an initial version and returns
// the CryptoKey resource name. An existing CryptoKey is never adopted.
func GCPProvisionKey(ctx context.Context, cfg GCPProvisionConfig) (string, error) {
	opts, err := GCPClientOptions(cfg.CredentialsFile)
	if err != nil {
		return "", err
	}
	client, err := kms.NewKeyManagementClient(ctx, opts...)
	if err != nil {
		return "", fmt.Errorf("new kms client: %w", err)
	}
	defer client.Close()
	return gcpProvisionKey(ctx, client, cfg)
}

func gcpProvisionKey(ctx context.Context, client gcpProvisionClient, cfg GCPProvisionConfig) (string, error) {
	if err := ensureKeyRing(ctx, client, cfg.Project, cfg.Location, cfg.KeyRing); err != nil {
		return "", err
	}
	keyRingName := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s", cfg.Project, cfg.Location, cfg.KeyRing)
	created, err := client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      keyRingName,
		CryptoKeyId: cfg.Key,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm:       kmspb.CryptoKeyVersion_EC_SIGN_ED25519,
				ProtectionLevel: cfg.Protection,
			},
		},
	})
	if err != nil {
		return "", fmt.Errorf("create crypto key: %w", err)
	}
	return created.Name, nil
}
