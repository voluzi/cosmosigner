package backend

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/cometbft/cometbft/crypto"
	cmted25519 "github.com/cometbft/cometbft/crypto/ed25519"
)

// AWSKMSConfig selects a key; credentials and region fall back to the AWS SDK chains.
type AWSKMSConfig struct {
	KeyID   string        `yaml:"key_id" env:"COSMOSIGNER_AWS_KEY_ID"`
	Region  string        `yaml:"region" env:"COSMOSIGNER_AWS_REGION"`
	Timeout time.Duration `yaml:"-" env:"COSMOSIGNER_AWS_TIMEOUT" default:"10s"`
}

// AWSKMS pins a single-Region key ARN and verifies every signature locally.
type AWSKMS struct {
	client  *kms.Client
	keyARN  string
	timeout time.Duration
	pub     cmted25519.PubKey
}

func awsTimeout(cfg AWSKMSConfig) time.Duration {
	if cfg.Timeout > 0 {
		return cfg.Timeout
	}
	return 10 * time.Second
}

func newAWSClient(ctx context.Context, cfg AWSKMSConfig) (*kms.Client, error) {
	var opts []func(*awsconfig.LoadOptions) error
	if cfg.Region != "" {
		opts = append(opts, awsconfig.WithRegion(cfg.Region))
	}
	loaded, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("load AWS configuration: %w", err)
	}
	return kms.NewFromConfig(loaded), nil
}

// NewAWSKMS resolves aliases once, validates PureEdDSA support, and caches the public key.
func NewAWSKMS(cfg AWSKMSConfig) (*AWSKMS, error) {
	if cfg.KeyID == "" {
		return nil, fmt.Errorf("awskms backend requires a key ID or ARN")
	}
	ctx, cancel := context.WithTimeout(context.Background(), awsTimeout(cfg))
	defer cancel()
	client, err := newAWSClient(ctx, cfg)
	if err != nil {
		return nil, err
	}
	resp, err := client.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: aws.String(cfg.KeyID)})
	if err != nil {
		return nil, fmt.Errorf("get AWS public key: %w", err)
	}
	if resp == nil {
		return nil, fmt.Errorf("empty AWS public key response")
	}
	keyARN := aws.ToString(resp.KeyId)
	if err := checkAWSKeyIdentity(cfg.KeyID, keyARN); err != nil {
		return nil, err
	}
	pub, err := parseAWSPublicKey(resp)
	if err != nil {
		return nil, err
	}
	return &AWSKMS{client: client, keyARN: keyARN, timeout: awsTimeout(cfg), pub: pub}, nil
}

func checkAWSKeyARN(keyARN string) error {
	parsed, err := arn.Parse(keyARN)
	if err != nil || parsed.Service != "kms" || parsed.Partition == "" || parsed.Region == "" || len(parsed.AccountID) != 12 || !strings.HasPrefix(parsed.Resource, "key/") {
		return fmt.Errorf("invalid AWS KMS key ARN %q", keyARN)
	}
	for _, c := range parsed.AccountID {
		if c < '0' || c > '9' {
			return fmt.Errorf("invalid AWS KMS account in ARN %q", keyARN)
		}
	}
	keyID := strings.TrimPrefix(parsed.Resource, "key/")
	if keyID == "" || strings.ContainsAny(keyID, "/ \t\r\n") {
		return fmt.Errorf("invalid AWS KMS key ARN %q", keyARN)
	}
	// Replicas share material but not tags, so regional claims cannot protect one history.
	if strings.HasPrefix(keyID, "mrk-") {
		return fmt.Errorf("multi-Region AWS KMS keys are unsupported: %s", keyARN)
	}
	return nil
}

func checkAWSKeyIdentity(requested, returned string) error {
	if err := checkAWSKeyARN(returned); err != nil {
		return err
	}
	if strings.HasPrefix(requested, "arn:") {
		parsed, err := arn.Parse(requested)
		if err != nil {
			return fmt.Errorf("invalid requested AWS ARN: %w", err)
		}
		if !strings.HasPrefix(parsed.Resource, "alias/") && requested != returned {
			return fmt.Errorf("AWS key ARN mismatch: requested %q, got %q", requested, returned)
		}
	} else if requested != "" && !strings.HasPrefix(requested, "alias/") {
		parsed, _ := arn.Parse(returned)
		if parsed.Resource != "key/"+requested {
			return fmt.Errorf("AWS key ID mismatch: requested %q, got %q", requested, returned)
		}
	}
	return nil
}

func parseAWSPublicKey(resp *kms.GetPublicKeyOutput) (cmted25519.PubKey, error) {
	if resp.KeySpec != types.KeySpecEccNistEdwards25519 {
		return nil, fmt.Errorf("AWS key spec %s, want ECC_NIST_EDWARDS25519", resp.KeySpec)
	}
	if resp.KeyUsage != types.KeyUsageTypeSignVerify {
		return nil, fmt.Errorf("AWS key usage %s, want SIGN_VERIFY", resp.KeyUsage)
	}
	if !slices.Contains(resp.SigningAlgorithms, types.SigningAlgorithmSpecEd25519Sha512) {
		return nil, fmt.Errorf("AWS key does not advertise ED25519_SHA_512")
	}
	parsed, err := x509.ParsePKIXPublicKey(resp.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("parse AWS public key: %w", err)
	}
	pub, ok := parsed.(ed25519.PublicKey)
	if !ok || len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("AWS public key is not a 32-byte ed25519 key (%T)", parsed)
	}
	return append(cmted25519.PubKey(nil), pub...), nil
}

// KeyARN returns the immutable key ARN pinned at construction.
func (a *AWSKMS) KeyARN() string { return a.keyARN }

func (a *AWSKMS) PubKey() (crypto.PubKey, error) {
	return append(cmted25519.PubKey(nil), a.pub...), nil
}
func (a *AWSKMS) Close() error { return nil }
func (a *AWSKMS) Sign(message []byte) ([]byte, error) {
	return a.signWithContext(context.Background(), message)
}
func (a *AWSKMS) signWithContext(ctx context.Context, message []byte) ([]byte, error) {
	if len(message) < 1 || len(message) > 4096 {
		return nil, fmt.Errorf("AWS RAW message size %d, want 1..4096 bytes", len(message))
	}
	ctx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()
	resp, err := a.client.Sign(ctx, &kms.SignInput{
		KeyId:            aws.String(a.keyARN),
		Message:          message,
		MessageType:      types.MessageTypeRaw,
		SigningAlgorithm: types.SigningAlgorithmSpecEd25519Sha512,
	})
	if err != nil {
		return nil, fmt.Errorf("AWS KMS sign: %w", err)
	}
	if resp == nil || aws.ToString(resp.KeyId) != a.keyARN {
		return nil, fmt.Errorf("AWS sign response key ARN mismatch")
	}
	if resp.SigningAlgorithm != types.SigningAlgorithmSpecEd25519Sha512 {
		return nil, fmt.Errorf("AWS sign response algorithm %s, want ED25519_SHA_512", resp.SigningAlgorithm)
	}
	if len(resp.Signature) != ed25519.SignatureSize {
		return nil, fmt.Errorf("AWS signature size %d, want %d", len(resp.Signature), ed25519.SignatureSize)
	}
	if !a.pub.VerifySignature(message, resp.Signature) {
		return nil, fmt.Errorf("AWS signature does not verify against pinned public key")
	}
	return resp.Signature, nil
}

// This text cannot be parsed as a canonical CometBFT vote or proposal.
var awsPreflightMessage = []byte("cosmosigner/awskms preflight - not a consensus message")

// VerifyCanSign checks permission, local verification, and empirical determinism before serving.
func (a *AWSKMS) VerifyCanSign(ctx context.Context) error {
	first, err := a.signWithContext(ctx, awsPreflightMessage)
	if err != nil {
		return fmt.Errorf("AWS key %s cannot sign preflight: %w", a.keyARN, err)
	}
	second, err := a.signWithContext(ctx, awsPreflightMessage)
	if err != nil {
		return fmt.Errorf("AWS key %s cannot repeat preflight: %w", a.keyARN, err)
	}
	if !bytes.Equal(first, second) {
		return fmt.Errorf("AWS key %s produced non-deterministic Ed25519 signatures", a.keyARN)
	}
	return nil
}
