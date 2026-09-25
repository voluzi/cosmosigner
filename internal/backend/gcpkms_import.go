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
	"github.com/googleapis/gax-go/v2"
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
// EC_SIGN_ED25519 key version and returns the version resource name plus whether
// it reached ENABLED. ready is false when the import was accepted but KMS is
// still finalizing the version (the caller cannot read its public key yet, so it
// must defer verification); it is always true alongside a nil error otherwise.
//
// Flow per Cloud KMS BYOK: create (or reuse) an ImportJob, wait until ACTIVE,
// wrap the key material with the job's RSA public key (RSA-OAEP SHA-256, empty
// label), then ImportCryptoKeyVersion. Existing resources are read, never
// re-created: the key ring and the target CryptoKey (with no initial version)
// are created only when the CryptoKey is missing, and an existing CryptoKey
// must be an ASYMMETRIC_SIGN EC_SIGN_ED25519 key at the requested protection
// level.
func GCPImportKey(ctx context.Context, cfg GCPImportConfig, pkcs8DER []byte) (version string, ready bool, err error) {
	opts, err := GCPClientOptions(cfg.CredentialsFile)
	if err != nil {
		return "", false, err
	}
	client, err := kms.NewKeyManagementClient(ctx, opts...)
	if err != nil {
		return "", false, fmt.Errorf("new kms client: %w", err)
	}
	defer client.Close()
	return gcpImportKey(ctx, client, cfg, pkcs8DER)
}

// gcpImportClient is the subset of the Cloud KMS client the BYOK import uses.
type gcpImportClient interface {
	GetKeyRing(context.Context, *kmspb.GetKeyRingRequest, ...gax.CallOption) (*kmspb.KeyRing, error)
	CreateKeyRing(context.Context, *kmspb.CreateKeyRingRequest, ...gax.CallOption) (*kmspb.KeyRing, error)
	GetCryptoKey(context.Context, *kmspb.GetCryptoKeyRequest, ...gax.CallOption) (*kmspb.CryptoKey, error)
	CreateCryptoKey(context.Context, *kmspb.CreateCryptoKeyRequest, ...gax.CallOption) (*kmspb.CryptoKey, error)
	GetImportJob(context.Context, *kmspb.GetImportJobRequest, ...gax.CallOption) (*kmspb.ImportJob, error)
	CreateImportJob(context.Context, *kmspb.CreateImportJobRequest, ...gax.CallOption) (*kmspb.ImportJob, error)
	ImportCryptoKeyVersion(context.Context, *kmspb.ImportCryptoKeyVersionRequest, ...gax.CallOption) (*kmspb.CryptoKeyVersion, error)
	GetCryptoKeyVersion(context.Context, *kmspb.GetCryptoKeyVersionRequest, ...gax.CallOption) (*kmspb.CryptoKeyVersion, error)
}

func gcpImportKey(ctx context.Context, client gcpImportClient, cfg GCPImportConfig, pkcs8DER []byte) (string, bool, error) {
	keyRingName := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s", cfg.Project, cfg.Location, cfg.KeyRing)
	keyName := keyRingName + "/cryptoKeys/" + cfg.Key
	jobName := keyRingName + "/importJobs/" + cfg.ImportJobID

	// Cloud KMS checks IAM before existence, so creating a resource that already
	// exists still needs its create permission. Read first and create only on
	// NotFound; an identity scoped to an existing key never needs create rights.
	if err := ensureImportCryptoKey(ctx, client, cfg, keyRingName, keyName); err != nil {
		return "", false, err
	}
	job, err := ensureImportJob(ctx, client, cfg, keyRingName, jobName)
	if err != nil {
		return "", false, err
	}

	// Wrap the PKCS#8 key with the job's RSA public key (OAEP SHA-256, no label).
	block, _ := pem.Decode([]byte(job.PublicKey.GetPem()))
	if block == nil {
		return "", false, fmt.Errorf("decode import job wrapping key PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", false, fmt.Errorf("parse wrapping key: %w", err)
	}
	rsaPub, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return "", false, fmt.Errorf("wrapping key is not RSA (%T)", parsed)
	}
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPub, pkcs8DER, nil)
	if err != nil {
		return "", false, fmt.Errorf("wrap key material: %w", err)
	}

	imported, err := client.ImportCryptoKeyVersion(ctx, &kmspb.ImportCryptoKeyVersionRequest{
		Parent:     keyName,
		Algorithm:  kmspb.CryptoKeyVersion_EC_SIGN_ED25519,
		ImportJob:  jobName,
		WrappedKey: wrapped,
	})
	if err != nil {
		return "", false, fmt.Errorf("import crypto key version: %w", err)
	}
	return waitVersionEnabled(ctx, client, imported.Name)
}

func waitImportJobActive(ctx context.Context, client gcpImportClient, name string) (*kmspb.ImportJob, error) {
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

func waitVersionEnabled(ctx context.Context, client gcpImportClient, name string) (string, bool, error) {
	deadline := time.Now().Add(2 * time.Minute)
	for {
		v, err := client.GetCryptoKeyVersion(ctx, &kmspb.GetCryptoKeyVersionRequest{Name: name})
		if err != nil {
			return "", false, fmt.Errorf("get crypto key version: %w", err)
		}
		switch v.State {
		case kmspb.CryptoKeyVersion_ENABLED:
			return name, true, nil
		case kmspb.CryptoKeyVersion_PENDING_IMPORT:
			if time.Now().After(deadline) {
				return name, false, nil // import accepted but not yet ENABLED; caller defers verification
			}
			select {
			case <-ctx.Done():
				return "", false, ctx.Err()
			case <-time.After(time.Second):
			}
		case kmspb.CryptoKeyVersion_IMPORT_FAILED:
			return "", false, fmt.Errorf("import failed: %s", v.ImportFailureReason)
		default:
			return "", false, fmt.Errorf("unexpected key version state %s", v.State)
		}
	}
}

// ensureImportCryptoKey makes sure the target CryptoKey exists and can take an
// imported EC_SIGN_ED25519 version at the requested protection level. The key
// ring is only looked up (and created) when the key itself is missing.
func ensureImportCryptoKey(ctx context.Context, client gcpImportClient, cfg GCPImportConfig, keyRingName, keyName string) error {
	key, err := client.GetCryptoKey(ctx, &kmspb.GetCryptoKeyRequest{Name: keyName})
	switch {
	case err == nil:
		return checkImportCryptoKey(key, cfg.Protection)
	case status.Code(err) != codes.NotFound:
		return fmt.Errorf("get crypto key: %w", err)
	}

	if _, err := client.GetKeyRing(ctx, &kmspb.GetKeyRingRequest{Name: keyRingName}); err != nil {
		if status.Code(err) != codes.NotFound {
			return fmt.Errorf("get key ring: %w", err)
		}
		if _, err := client.CreateKeyRing(ctx, &kmspb.CreateKeyRingRequest{
			Parent:    fmt.Sprintf("projects/%s/locations/%s", cfg.Project, cfg.Location),
			KeyRingId: cfg.KeyRing,
			KeyRing:   &kmspb.KeyRing{},
		}); err != nil && status.Code(err) != codes.AlreadyExists {
			return fmt.Errorf("create key ring: %w", err)
		}
	}

	// Target crypto key with no initial version.
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
	}); err != nil {
		if status.Code(err) != codes.AlreadyExists {
			return fmt.Errorf("create crypto key: %w", err)
		}
		// Lost a creation race: validate what the other writer created.
		key, err := client.GetCryptoKey(ctx, &kmspb.GetCryptoKeyRequest{Name: keyName})
		if err != nil {
			return fmt.Errorf("get crypto key: %w", err)
		}
		return checkImportCryptoKey(key, cfg.Protection)
	}
	return nil
}

func checkImportCryptoKey(key *kmspb.CryptoKey, protection kmspb.ProtectionLevel) error {
	tmpl := key.GetVersionTemplate()
	if key.GetPurpose() != kmspb.CryptoKey_ASYMMETRIC_SIGN ||
		tmpl.GetAlgorithm() != kmspb.CryptoKeyVersion_EC_SIGN_ED25519 ||
		tmpl.GetProtectionLevel() != protection {
		return fmt.Errorf("crypto key %s has purpose %s, algorithm %s, protection %s; cosmosigner requires %s, %s, %s (the protection level comes from --gcp-protection)",
			key.GetName(), key.GetPurpose(), tmpl.GetAlgorithm(), tmpl.GetProtectionLevel(),
			kmspb.CryptoKey_ASYMMETRIC_SIGN, kmspb.CryptoKeyVersion_EC_SIGN_ED25519, protection)
	}
	return nil
}

// ensureImportJob reuses the named ImportJob or creates it on NotFound, waits
// until it is ACTIVE, and checks it matches the wrapping this import performs.
func ensureImportJob(ctx context.Context, client gcpImportClient, cfg GCPImportConfig, keyRingName, jobName string) (*kmspb.ImportJob, error) {
	if _, err := client.GetImportJob(ctx, &kmspb.GetImportJobRequest{Name: jobName}); err != nil {
		if status.Code(err) != codes.NotFound {
			return nil, fmt.Errorf("get import job: %w", err)
		}
		if _, err := client.CreateImportJob(ctx, &kmspb.CreateImportJobRequest{
			Parent:      keyRingName,
			ImportJobId: cfg.ImportJobID,
			ImportJob: &kmspb.ImportJob{
				ImportMethod:    kmspb.ImportJob_RSA_OAEP_3072_SHA256,
				ProtectionLevel: cfg.Protection,
			},
		}); err != nil && status.Code(err) != codes.AlreadyExists {
			return nil, fmt.Errorf("create import job: %w", err)
		}
	}
	job, err := waitImportJobActive(ctx, client, jobName)
	if err != nil {
		return nil, err
	}
	// Only the direct RSA-OAEP-SHA256 methods match the wrapping done here.
	directOAEP := job.ImportMethod == kmspb.ImportJob_RSA_OAEP_3072_SHA256 || job.ImportMethod == kmspb.ImportJob_RSA_OAEP_4096_SHA256
	if !directOAEP || job.ProtectionLevel != cfg.Protection {
		return nil, fmt.Errorf("import job %s has method %s, protection %s; need %s or %s, %s (pass a new --gcp-import-job)",
			jobName, job.ImportMethod, job.ProtectionLevel, kmspb.ImportJob_RSA_OAEP_3072_SHA256, kmspb.ImportJob_RSA_OAEP_4096_SHA256, cfg.Protection)
	}
	return job, nil
}
