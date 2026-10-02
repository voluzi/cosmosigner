package backend

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// AWSProvisionKey creates a new single-Region Ed25519 key and returns its ARN.
func AWSProvisionKey(ctx context.Context, cfg AWSKMSConfig) (string, error) {
	if cfg.KeyID != "" {
		return "", fmt.Errorf("AWS provision creates a new key; omit --aws-key-id (including COSMOSIGNER_AWS_KEY_ID)")
	}
	ctx, cancel := context.WithTimeout(ctx, awsTimeout(cfg))
	defer cancel()
	client, err := newAWSClient(ctx, cfg)
	if err != nil {
		return "", err
	}
	return createAWSKey(ctx, client, types.OriginTypeAwsKms)
}

func createAWSKey(ctx context.Context, client *kms.Client, origin types.OriginType) (string, error) {
	// CreateKey has no idempotency token. A lost response must not create a second key.
	resp, err := client.CreateKey(ctx, &kms.CreateKeyInput{
		KeySpec:     types.KeySpecEccNistEdwards25519,
		KeyUsage:    types.KeyUsageTypeSignVerify,
		Origin:      origin,
		MultiRegion: aws.Bool(false),
	}, func(o *kms.Options) { o.Retryer = aws.NopRetryer{} })
	if err != nil {
		return "", fmt.Errorf("create AWS key (not retried; inspect KMS for a created key before retrying): %w", err)
	}
	if resp == nil {
		return "", fmt.Errorf("empty AWS CreateKey response")
	}
	state := types.KeyStateEnabled
	if origin == types.OriginTypeExternal {
		state = types.KeyStatePendingImport
	}
	if err := checkAWSMetadata(resp.KeyMetadata, "", origin, state); err != nil {
		keyARN := ""
		if resp.KeyMetadata != nil {
			keyARN = aws.ToString(resp.KeyMetadata.Arn)
		}
		return keyARN, fmt.Errorf("validate created AWS key %q: %w", keyARN, err)
	}
	return aws.ToString(resp.KeyMetadata.Arn), nil
}

func checkAWSMetadata(meta *types.KeyMetadata, requested string, origin types.OriginType, state types.KeyState) error {
	if meta == nil {
		return fmt.Errorf("empty AWS key metadata")
	}
	keyARN := aws.ToString(meta.Arn)
	if err := checkAWSKeyIdentity(requested, keyARN); err != nil {
		return err
	}
	parsed, _ := arn.Parse(keyARN)
	if parsed.Resource != "key/"+aws.ToString(meta.KeyId) {
		return fmt.Errorf("AWS key metadata ID/ARN mismatch")
	}
	if aws.ToBool(meta.MultiRegion) {
		return fmt.Errorf("multi-Region AWS KMS keys are unsupported")
	}
	if meta.KeySpec != types.KeySpecEccNistEdwards25519 || meta.KeyUsage != types.KeyUsageTypeSignVerify || meta.Origin != origin || meta.KeyManager != types.KeyManagerTypeCustomer {
		return fmt.Errorf("AWS key metadata requires customer-managed ECC_NIST_EDWARDS25519 SIGN_VERIFY with origin %s", origin)
	}
	if meta.KeyState != state {
		return fmt.Errorf("AWS key state %s, want %s", meta.KeyState, state)
	}
	return nil
}
