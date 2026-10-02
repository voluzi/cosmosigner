package backend

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// AWSImportKey imports PKCS#8 Ed25519 material into a new or PendingImport EXTERNAL key.
// ready is true only after the pinned public key matches the source. A false ready with
// no error means AWS accepted the material but its public key is not yet readable.
// Errors after target resolution return its ARN so an operator can inspect and resume.
// Retain a protected recovery copy: AWS makes the customer responsible for imported material.
func AWSImportKey(ctx context.Context, cfg AWSKMSConfig, pkcs8DER []byte) (resultARN string, ready bool, resultErr error) {
	parsed, err := x509.ParsePKCS8PrivateKey(pkcs8DER)
	if err != nil {
		return "", false, fmt.Errorf("parse import PKCS#8: %w", err)
	}
	source, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(source) != ed25519.PrivateKeySize {
		return "", false, fmt.Errorf("import material must be an Ed25519 PKCS#8 private key")
	}
	if strings.HasPrefix(cfg.KeyID, "alias/") {
		return "", false, fmt.Errorf("AWS import requires a key ID or key ARN; aliases are unsupported")
	}
	if strings.HasPrefix(cfg.KeyID, "arn:") {
		target, err := arn.Parse(cfg.KeyID)
		if err != nil || strings.HasPrefix(target.Resource, "alias/") {
			return "", false, fmt.Errorf("AWS import requires a key ID or key ARN; aliases are unsupported")
		}
	}
	cctx, cancel := context.WithTimeout(ctx, awsTimeout(cfg))
	defer cancel()
	client, err := newAWSClient(cctx, cfg)
	if err != nil {
		return "", false, err
	}
	keyARN := ""
	materialImported := false
	defer func() {
		if resultErr != nil && keyARN != "" {
			resultARN = keyARN
			if materialImported {
				verify := "cosmosigner pubkey --backend awskms --aws-key-id " + keyARN
				if cfg.Region != "" {
					verify += " --aws-region " + cfg.Region
				}
				resultErr = fmt.Errorf("AWS import into %s accepted; do not re-import; verify identity with %s: %w", keyARN, verify, resultErr)
				return
			}
			resultErr = fmt.Errorf("AWS import target %s; inspect key state before resuming with --aws-key-id %s: %w", keyARN, keyARN, resultErr)
		}
	}()
	if cfg.KeyID == "" {
		keyARN, err = createAWSKey(cctx, client, types.OriginTypeExternal)
		if err != nil {
			return "", false, err
		}
	} else {
		resp, err := client.DescribeKey(cctx, &kms.DescribeKeyInput{KeyId: aws.String(cfg.KeyID)})
		if err != nil {
			return "", false, fmt.Errorf("describe AWS import target: %w", err)
		}
		if resp == nil {
			return "", false, fmt.Errorf("empty AWS DescribeKey response")
		}
		if err := checkAWSMetadata(resp.KeyMetadata, cfg.KeyID, types.OriginTypeExternal, types.KeyStatePendingImport); err != nil {
			return "", false, err
		}
		keyARN = aws.ToString(resp.KeyMetadata.Arn)
		target := &AWSKMS{client: client, keyARN: keyARN, timeout: awsTimeout(cfg)}
		// PendingImport can be a recovery after material deletion. AWS permits only the
		// original immutable material to be restored; a valid history claim stays intact.
		if _, err := target.ClusterBinding(cctx); err != nil && !errors.Is(err, ErrBindingUnclaimed) {
			return "", false, fmt.Errorf("read AWS import target claim: %w", err)
		}
	}
	params, err := awsImportParameters(cctx, client, keyARN)
	if err != nil {
		return "", false, err
	}
	if params == nil || aws.ToString(params.KeyId) != keyARN {
		return "", false, fmt.Errorf("AWS import parameters key ARN mismatch")
	}
	if len(params.ImportToken) == 0 || params.ParametersValidTo == nil || !params.ParametersValidTo.After(time.Now()) {
		return "", false, fmt.Errorf("AWS import token is missing or expired")
	}
	parsedWrapping, err := x509.ParsePKIXPublicKey(params.PublicKey)
	if err != nil {
		return "", false, fmt.Errorf("parse AWS import wrapping public key: %w", err)
	}
	wrapping, ok := parsedWrapping.(*rsa.PublicKey)
	if !ok || wrapping.N.BitLen() != 4096 {
		return "", false, fmt.Errorf("AWS import wrapping key must be RSA_4096")
	}
	encrypted, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, wrapping, pkcs8DER, nil)
	if err != nil {
		return "", false, fmt.Errorf("wrap AWS import material: %w", err)
	}
	resp, err := client.ImportKeyMaterial(cctx, &kms.ImportKeyMaterialInput{
		KeyId:                aws.String(keyARN),
		ImportToken:          params.ImportToken,
		EncryptedKeyMaterial: encrypted,
		ExpirationModel:      types.ExpirationModelTypeKeyMaterialDoesNotExpire,
	})
	if err != nil {
		return "", false, fmt.Errorf("import AWS key material into %s: %w", keyARN, err)
	}
	materialImported = true
	if resp == nil || aws.ToString(resp.KeyId) != keyARN {
		return "", false, fmt.Errorf("AWS import response key ARN mismatch")
	}
	want := source.Public().(ed25519.PublicKey)
	for attempt := 0; attempt < awsConsistencyAttempts; attempt++ {
		pubResp, err := client.GetPublicKey(cctx, &kms.GetPublicKeyInput{KeyId: aws.String(keyARN)})
		if err == nil {
			if pubResp == nil || aws.ToString(pubResp.KeyId) != keyARN {
				return "", false, fmt.Errorf("AWS imported public key ARN mismatch")
			}
			pub, err := parseAWSPublicKey(pubResp)
			if err != nil {
				return "", false, err
			}
			if !bytes.Equal(pub, want) {
				return "", false, fmt.Errorf("imported AWS key %s public key MISMATCH with source", keyARN)
			}
			return keyARN, true, nil
		}
		if !awsImportNotReady(err) {
			return keyARN, false, nil
		}
		if attempt+1 < awsConsistencyAttempts {
			if err := waitAWSConsistency(cctx); err != nil {
				return keyARN, false, nil
			}
		}
	}
	return keyARN, false, nil
}

func awsImportParameters(ctx context.Context, client *kms.Client, keyARN string) (*kms.GetParametersForImportOutput, error) {
	for attempt := 0; attempt < awsConsistencyAttempts; attempt++ {
		params, err := client.GetParametersForImport(ctx, &kms.GetParametersForImportInput{
			KeyId:             aws.String(keyARN),
			WrappingAlgorithm: types.AlgorithmSpecRsaesOaepSha256,
			WrappingKeySpec:   types.WrappingKeySpecRsa4096,
		})
		if err == nil {
			return params, nil
		}
		var notFound *types.NotFoundException
		if !errors.As(err, &notFound) || attempt+1 == awsConsistencyAttempts {
			return nil, fmt.Errorf("get AWS import parameters for %s: %w", keyARN, err)
		}
		if err := waitAWSConsistency(ctx); err != nil {
			return nil, err
		}
	}
	return nil, fmt.Errorf("AWS import parameters unavailable for %s", keyARN)
}

func awsImportNotReady(err error) bool {
	var notFound *types.NotFoundException
	var invalidState *types.KMSInvalidStateException
	return errors.As(err, &notFound) || errors.As(err, &invalidState)
}
