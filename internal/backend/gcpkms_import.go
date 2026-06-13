package backend

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// GCPImportConfig configures a BYOK import into Cloud KMS.
type GCPImportConfig struct {
	Project         string
	Location        string
	KeyRing         string
	Key             string
	ImportJobID     string // created if absent; must be ACTIVE if it exists
	Protection      kmspb.ProtectionLevel
	CredentialsFile string
}

// GCPImportKey imports a PKCS#8 DER ed25519 private key into Cloud KMS as an
// EC_SIGN_ED25519 key version and returns the version resource name.
//
// Flow per Cloud KMS BYOK: create (or reuse) an ImportJob, wait until ACTIVE,
// wrap the key material with the job's RSA public key (RSA-OAEP SHA-256, empty
// label), then ImportCryptoKeyVersion. The target CryptoKey is created with no
// initial version.
func GCPImportKey(ctx context.Context, cfg GCPImportConfig, pkcs8DER []byte) (string, error) {
	opts, err := GCPClientOptions(cfg.CredentialsFile)
	if err != nil {
		return "", err
	}
	client, err := kms.NewKeyManagementClient(ctx, opts...)
	if err != nil {
		return "", fmt.Errorf("new kms client: %w", err)
	}
	defer client.Close()

	keyRingName := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s", cfg.Project, cfg.Location, cfg.KeyRing)

	// Key ring (idempotent).
	if _, err := client.CreateKeyRing(ctx, &kmspb.CreateKeyRingRequest{
		Parent:    fmt.Sprintf("projects/%s/locations/%s", cfg.Project, cfg.Location),
		KeyRingId: cfg.KeyRing,
		KeyRing:   &kmspb.KeyRing{},
	}); err != nil && status.Code(err) != codes.AlreadyExists {
		return "", fmt.Errorf("create key ring: %w", err)
	}

	// Target crypto key with no initial version (idempotent).
	keyName := keyRingName + "/cryptoKeys/" + cfg.Key
	if _, err := client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      keyRingName,
		CryptoKeyId: cfg.Key,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm:       kmspb.CryptoKeyVersion_EC_SIGN_ED25519,
				ProtectionLevel: cfg.Protection,
			},
		},
		SkipInitialVersionCreation: true,
	}); err != nil && status.Code(err) != codes.AlreadyExists {
		return "", fmt.Errorf("create crypto key: %w", err)
	}

	// Import job (idempotent), then wait for ACTIVE.
	jobName := keyRingName + "/importJobs/" + cfg.ImportJobID
	if _, err := client.CreateImportJob(ctx, &kmspb.CreateImportJobRequest{
		Parent:      keyRingName,
		ImportJobId: cfg.ImportJobID,
		ImportJob: &kmspb.ImportJob{
			ImportMethod:    kmspb.ImportJob_RSA_OAEP_3072_SHA256,
			ProtectionLevel: cfg.Protection,
		},
	}); err != nil && status.Code(err) != codes.AlreadyExists {
		return "", fmt.Errorf("create import job: %w", err)
	}
	job, err := waitImportJobActive(ctx, client, jobName)
	if err != nil {
		return "", err
	}

	// Wrap the PKCS#8 key with the job's RSA public key (OAEP SHA-256, no label).
	block, _ := pem.Decode([]byte(job.PublicKey.GetPem()))
	if block == nil {
		return "", fmt.Errorf("decode import job wrapping key PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse wrapping key: %w", err)
	}
	rsaPub, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return "", fmt.Errorf("wrapping key is not RSA (%T)", parsed)
	}
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPub, pkcs8DER, nil)
	if err != nil {
		return "", fmt.Errorf("wrap key material: %w", err)
	}

	version, err := client.ImportCryptoKeyVersion(ctx, &kmspb.ImportCryptoKeyVersionRequest{
		Parent:     keyName,
		Algorithm:  kmspb.CryptoKeyVersion_EC_SIGN_ED25519,
		ImportJob:  jobName,
		WrappedKey: wrapped,
	})
	if err != nil {
		return "", fmt.Errorf("import crypto key version: %w", err)
	}
	return waitVersionEnabled(ctx, client, version.Name)
}

func waitImportJobActive(ctx context.Context, client *kms.KeyManagementClient, name string) (*kmspb.ImportJob, error) {
	for {
		job, err := client.GetImportJob(ctx, &kmspb.GetImportJobRequest{Name: name})
		if err != nil {
			return nil, fmt.Errorf("get import job: %w", err)
		}
		switch job.State {
		case kmspb.ImportJob_ACTIVE:
			return job, nil
		case kmspb.ImportJob_PENDING_GENERATION:
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Second):
			}
		default:
			return nil, fmt.Errorf("import job %s is %s (expired jobs cannot be reused — pass a new --gcp-import-job)", name, job.State)
		}
	}
}

func waitVersionEnabled(ctx context.Context, client *kms.KeyManagementClient, name string) (string, error) {
	deadline := time.Now().Add(2 * time.Minute)
	for {
		v, err := client.GetCryptoKeyVersion(ctx, &kmspb.GetCryptoKeyVersionRequest{Name: name})
		if err != nil {
			return "", fmt.Errorf("get crypto key version: %w", err)
		}
		switch v.State {
		case kmspb.CryptoKeyVersion_ENABLED:
			return name, nil
		case kmspb.CryptoKeyVersion_PENDING_IMPORT:
			if time.Now().After(deadline) {
				return name, nil // import accepted; let the user poll
			}
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(time.Second):
			}
		case kmspb.CryptoKeyVersion_IMPORT_FAILED:
			return "", fmt.Errorf("import failed: %s", v.ImportFailureReason)
		default:
			return "", fmt.Errorf("unexpected key version state %s", v.State)
		}
	}
}
