package backend

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"hash/crc32"
	"os"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/api/option"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/cometbft/cometbft/crypto"
	cmted25519 "github.com/cometbft/cometbft/crypto/ed25519"
)

// GCPKMSConfig configures the Google Cloud KMS backend.
type GCPKMSConfig struct {
	// KeyVersion is the full cryptoKeyVersion resource name, e.g.
	// projects/P/locations/L/keyRings/R/cryptoKeys/K/cryptoKeyVersions/V
	KeyVersion string `yaml:"key_version" env:"COSMOSIGNER_GCP_KEY_VERSION"`
	// CredentialsFile is optional; falls back to Application Default Credentials.
	CredentialsFile string        `yaml:"credentials_file" env:"COSMOSIGNER_GCP_CREDENTIALS_FILE"`
	Timeout         time.Duration `yaml:"-" env:"COSMOSIGNER_GCP_TIMEOUT" default:"10s"`
}

// GCPKMS signs via a Cloud KMS EC_SIGN_ED25519 key (PureEdDSA, raw input). The
// private key never leaves KMS; the public key is fetched once and cached.
type GCPKMS struct {
	client     *kms.KeyManagementClient
	keyVersion string
	timeout    time.Duration
	pub        crypto.PubKey
}

var crc32cTable = crc32.MakeTable(crc32.Castagnoli)

// credTypeFromJSON infers the credentials type from the JSON content so we
// can use the non-deprecated WithAuthCredentialsJSON.
func credTypeFromJSON(data []byte) (option.CredentialsType, error) {
	var f struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		return "", fmt.Errorf("parse credentials type: %w", err)
	}
	switch f.Type {
	case "service_account":
		return option.ServiceAccount, nil
	case "authorized_user":
		return option.AuthorizedUser, nil
	case "impersonated_service_account":
		return option.ImpersonatedServiceAccount, nil
	case "external_account":
		return option.ExternalAccount, nil
	case "gdc_service_account":
		return option.CredentialsType("gdc_service_account"), nil
	case "external_account_authorized_user":
		return option.CredentialsType("external_account_authorized_user"), nil
	default:
		return "", fmt.Errorf("unknown credentials type: %q", f.Type)
	}
}

// GCPClientOptions builds Cloud KMS client options. When credsFile is set, its
// JSON is read and passed explicitly; otherwise Application Default Credentials
// are used (workload identity, GOOGLE_APPLICATION_CREDENTIALS, etc.).
func GCPClientOptions(credsFile string) ([]option.ClientOption, error) {
	if credsFile == "" {
		return nil, nil
	}
	data, err := os.ReadFile(credsFile)
	if err != nil {
		return nil, fmt.Errorf("read credentials file: %w", err)
	}
	credType, err := credTypeFromJSON(data)
	if err != nil {
		return nil, err
	}
	return []option.ClientOption{option.WithAuthCredentialsJSON(credType, data)}, nil
}

// NewGCPKMS connects to Cloud KMS, validates the key algorithm, and caches the
// public key.
func NewGCPKMS(cfg GCPKMSConfig) (*GCPKMS, error) {
	if cfg.KeyVersion == "" {
		return nil, fmt.Errorf("gcpkms backend requires a key version resource name")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}

	ctx := context.Background()
	opts, err := GCPClientOptions(cfg.CredentialsFile)
	if err != nil {
		return nil, err
	}
	client, err := kms.NewKeyManagementClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("new kms client: %w", err)
	}

	g := &GCPKMS{client: client, keyVersion: cfg.KeyVersion, timeout: cfg.Timeout}
	pub, err := g.fetchPubKey(ctx)
	if err != nil {
		_ = client.Close()
		return nil, err
	}
	g.pub = pub
	return g, nil
}

func (g *GCPKMS) PubKey() (crypto.PubKey, error) { return g.pub, nil }

// gcpPreflightMessage is signed by VerifyCanSign to prove the key is usable. It
// is deliberately NOT valid CometBFT canonical sign-bytes (which are a
// length-delimited CanonicalVote/CanonicalProposal protobuf), so signing it can
// never be mistaken for a consensus message — the preflight cannot contribute
// to a double-sign.
var gcpPreflightMessage = []byte("cosmosigner/gcpkms preflight — not a consensus message")

// VerifyCanSign checks at startup that the KMS key can actually sign, so a
// misconfiguration fails fast at boot instead of at the first consensus vote.
// NewGCPKMS only proves GetPublicKey access; an IAM policy can grant that while
// withholding AsymmetricSign (roles/cloudkms.signerVerifier), and the key
// version may not be ENABLED. This signs a non-consensus probe and verifies the
// result against the cached public key, so a broken policy, a disabled key, or a
// signature that does not match the advertised identity are all caught here.
func (g *GCPKMS) VerifyCanSign() error {
	sig, err := g.Sign(gcpPreflightMessage)
	if err != nil {
		return fmt.Errorf("kms key %q cannot sign (needs roles/cloudkms.signerVerifier and an ENABLED version): %w", g.keyVersion, err)
	}
	if !g.pub.VerifySignature(gcpPreflightMessage, sig) {
		return fmt.Errorf("kms key %q produced a signature that does not verify against its public key", g.keyVersion)
	}
	return nil
}

func (g *GCPKMS) Sign(signBytes []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), g.timeout)
	defer cancel()

	dataCRC := int64(crc32.Checksum(signBytes, crc32cTable))
	resp, err := g.client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name:       g.keyVersion,
		Data:       signBytes, // PureEdDSA: raw data, not a digest
		DataCrc32C: wrapperspb.Int64(dataCRC),
	})
	if err != nil {
		return nil, fmt.Errorf("kms asymmetric sign: %w", err)
	}
	// Integrity checks per Cloud KMS guidance.
	if !resp.VerifiedDataCrc32C {
		return nil, fmt.Errorf("kms did not verify request data integrity")
	}
	if resp.Name != g.keyVersion {
		return nil, fmt.Errorf("kms response key mismatch: got %q", resp.Name)
	}
	sig := resp.Signature
	if resp.SignatureCrc32C == nil || int64(crc32.Checksum(sig, crc32cTable)) != resp.SignatureCrc32C.Value {
		return nil, fmt.Errorf("kms response signature corrupted in transit")
	}
	if len(sig) != cmted25519.SignatureSize {
		return nil, fmt.Errorf("signature size %d, want %d", len(sig), cmted25519.SignatureSize)
	}
	return sig, nil
}

func (g *GCPKMS) Close() error { return g.client.Close() }

func (g *GCPKMS) fetchPubKey(ctx context.Context) (crypto.PubKey, error) {
	cctx, cancel := context.WithTimeout(ctx, g.timeout)
	defer cancel()

	resp, err := g.client.GetPublicKey(cctx, &kmspb.GetPublicKeyRequest{Name: g.keyVersion})
	if err != nil {
		return nil, fmt.Errorf("get public key: %w", err)
	}
	if resp.Algorithm != kmspb.CryptoKeyVersion_EC_SIGN_ED25519 {
		return nil, fmt.Errorf("key algorithm is %v, want EC_SIGN_ED25519", resp.Algorithm)
	}
	block, _ := pem.Decode([]byte(resp.Pem))
	if block == nil {
		return nil, fmt.Errorf("failed to decode public key PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	edPub, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not ed25519 (%T)", parsed)
	}
	if len(edPub) != cmted25519.PubKeySize {
		return nil, fmt.Errorf("ed25519 public key size %d, want %d", len(edPub), cmted25519.PubKeySize)
	}
	pk := make(cmted25519.PubKey, cmted25519.PubKeySize)
	copy(pk, edPub)
	return pk, nil
}
