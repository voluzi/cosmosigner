package backend

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/voluzi/cosmosigner/internal/clusterid"
)

func awsImportSource(t *testing.T) []byte {
	t.Helper()
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return der
}

func TestAWSKMSImportRoundTrip(t *testing.T) {
	wrapping, err := rsa.GenerateKey(rand.Reader, 4096)
	require.NoError(t, err)
	wrappingDER, err := x509.MarshalPKIXPublicKey(&wrapping.PublicKey)
	require.NoError(t, err)
	source := awsImportSource(t)
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	pubResponse := awsPublicResponse(t, key)
	id, err := clusterid.New()
	require.NoError(t, err)
	for _, mode := range []string{"new", "existing", "recovery"} {
		t.Run(mode, func(t *testing.T) {
			var creates, imports, params, pubs atomic.Int32
			cfg := AWSKMSConfig{Timeout: 5 * time.Second}
			if mode != "new" {
				cfg.KeyID = "12345678-1234-1234-1234-123456789012"
			}
			token := []byte("test-import-token")
			awsTestServer(t, func(op string, raw json.RawMessage) (any, int) {
				var req struct {
					KeyId, KeySpec, KeyUsage, Origin, WrappingAlgorithm, WrappingKeySpec, ExpirationModel string
					MultiRegion                                                                           bool
					ImportToken, EncryptedKeyMaterial                                                     []byte
					ValidTo                                                                               *float64
				}
				assert.NoError(t, json.Unmarshal(raw, &req))
				switch op {
				case "CreateKey":
					creates.Add(1)
					assert.Equal(t, "new", mode)
					assert.Equal(t, "EXTERNAL", req.Origin)
					assert.Equal(t, "ECC_NIST_EDWARDS25519", req.KeySpec)
					assert.Equal(t, "SIGN_VERIFY", req.KeyUsage)
					assert.False(t, req.MultiRegion)
					return map[string]any{"KeyMetadata": awsMetadata("EXTERNAL", "PendingImport")}, 200
				case "DescribeKey":
					assert.Equal(t, cfg.KeyID, req.KeyId)
					return map[string]any{"KeyMetadata": awsMetadata("EXTERNAL", "PendingImport")}, 200
				case "ListResourceTags":
					assert.Equal(t, testAWSARN, req.KeyId)
					if mode == "recovery" {
						return map[string]any{"Tags": []map[string]string{{"TagKey": "cosmosigner-cluster-id", "TagValue": id}}}, 200
					}
					return map[string]any{}, 200
				case "GetParametersForImport":
					assert.Equal(t, testAWSARN, req.KeyId)
					assert.Equal(t, "RSAES_OAEP_SHA_256", req.WrappingAlgorithm)
					assert.Equal(t, "RSA_4096", req.WrappingKeySpec)
					if params.Add(1) == 1 {
						return map[string]any{"__type": "NotFoundException", "message": "not yet visible"}, 400
					}
					return map[string]any{"KeyId": testAWSARN, "PublicKey": wrappingDER, "ImportToken": token, "ParametersValidTo": float64(time.Now().Add(time.Hour).Unix())}, 200
				case "ImportKeyMaterial":
					imports.Add(1)
					assert.Equal(t, testAWSARN, req.KeyId)
					assert.Equal(t, token, req.ImportToken)
					assert.Equal(t, "KEY_MATERIAL_DOES_NOT_EXPIRE", req.ExpirationModel)
					assert.Nil(t, req.ValidTo)
					plain, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, wrapping, req.EncryptedKeyMaterial, nil)
					assert.NoError(t, err)
					assert.True(t, bytes.Equal(source, plain))
					return map[string]any{"KeyId": testAWSARN}, 200
				case "GetPublicKey":
					assert.Equal(t, testAWSARN, req.KeyId)
					if pubs.Add(1) == 1 {
						return map[string]any{"__type": "KMSInvalidStateException", "message": "finalizing"}, 400
					}
					return pubResponse, 200
				default:
					t.Errorf("unexpected AWS call %s", op)
					return map[string]any{}, 400
				}
			})
			got, ready, err := AWSImportKey(t.Context(), cfg, source)
			require.NoError(t, err)
			require.True(t, ready)
			require.Equal(t, testAWSARN, got)
			require.EqualValues(t, 1, imports.Load())
			require.EqualValues(t, 2, params.Load())
			require.EqualValues(t, 2, pubs.Load())
			if mode == "new" {
				require.EqualValues(t, 1, creates.Load())
			} else {
				require.Zero(t, creates.Load())
			}
		})
	}
}

func TestAWSKMSImportRejectsUnsafeTarget(t *testing.T) {
	for _, tc := range []struct {
		name, wantError string
		mutate          func(map[string]any)
		claim           string
		denied          bool
	}{
		{name: "wrong origin", wantError: "metadata", mutate: func(m map[string]any) { m["Origin"] = "AWS_KMS" }},
		{name: "enabled", wantError: "PendingImport", mutate: func(m map[string]any) { m["KeyState"] = "Enabled" }},
		{name: "wrong usage", wantError: "metadata", mutate: func(m map[string]any) { m["KeyUsage"] = "ENCRYPT_DECRYPT" }},
		{name: "managed key", wantError: "metadata", mutate: func(m map[string]any) { m["KeyManager"] = "AWS" }},
		{name: "multi Region", wantError: "multi-Region", mutate: func(m map[string]any) { m["MultiRegion"] = true }},
		{name: "wrong identity", wantError: "mismatch", mutate: func(m map[string]any) { m["Arn"] = otherAWSARN }},
		{name: "corrupt claim", claim: "bad", wantError: "corrupt"},
		{name: "unreadable claim", denied: true, wantError: "unreadable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			metadata := awsMetadata("EXTERNAL", "PendingImport")
			if tc.mutate != nil {
				tc.mutate(metadata)
			}
			var writes atomic.Int32
			awsTestServer(t, func(op string, raw json.RawMessage) (any, int) {
				switch op {
				case "DescribeKey":
					return map[string]any{"KeyMetadata": metadata}, 200
				case "ListResourceTags":
					if tc.denied {
						return map[string]any{"__type": "AccessDeniedException", "message": "denied"}, 400
					}
					return map[string]any{"Tags": []map[string]string{{"TagKey": "cosmosigner-cluster-id", "TagValue": tc.claim}}}, 200
				default:
					writes.Add(1)
					return map[string]any{}, 400
				}
			})
			_, _, err := AWSImportKey(t.Context(), AWSKMSConfig{KeyID: testAWSARN}, awsImportSource(t))
			require.ErrorContains(t, err, tc.wantError)
			require.Zero(t, writes.Load())
		})
	}
}

func TestAWSKMSImportResponseIntegrity(t *testing.T) {
	wrapping, err := rsa.GenerateKey(rand.Reader, 4096)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&wrapping.PublicKey)
	require.NoError(t, err)
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	otherResponse := awsPublicResponse(t, other)
	for _, mode := range []string{"parameters ARN", "missing token", "expired token", "invalid wrapping key", "import ARN", "public ARN", "public identity", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var imports atomic.Int32
			pubResponse := awsPublicResponse(t, ed25519.NewKeyFromSeed(make([]byte, 32)))
			awsTestServer(t, func(op string, raw json.RawMessage) (any, int) {
				switch op {
				case "DescribeKey":
					return map[string]any{"KeyMetadata": awsMetadata("EXTERNAL", "PendingImport")}, 200
				case "ListResourceTags":
					return map[string]any{}, 200
				case "GetParametersForImport":
					response := map[string]any{"KeyId": testAWSARN, "PublicKey": der, "ImportToken": []byte("token"), "ParametersValidTo": float64(time.Now().Add(time.Hour).Unix())}
					switch mode {
					case "parameters ARN":
						response["KeyId"] = otherAWSARN
					case "missing token":
						delete(response, "ImportToken")
					case "expired token":
						response["ParametersValidTo"] = float64(time.Now().Add(-time.Hour).Unix())
					case "invalid wrapping key":
						response["PublicKey"] = []byte{1, 2}
					case "cancelled":
						cancel()
						return map[string]any{"__type": "NotFoundException", "message": "not yet visible"}, 400
					}
					return response, 200
				case "ImportKeyMaterial":
					imports.Add(1)
					keyID := testAWSARN
					if mode == "import ARN" {
						keyID = otherAWSARN
					}
					return map[string]any{"KeyId": keyID}, 200
				case "GetPublicKey":
					if mode == "public ARN" {
						pubResponse["KeyId"] = otherAWSARN
					}
					if mode == "public identity" {
						return otherResponse, 200
					}
					return pubResponse, 200
				default:
					t.Errorf("unexpected AWS call %s", op)
					return map[string]any{}, 400
				}
			})
			_, ready, err := AWSImportKey(ctx, AWSKMSConfig{KeyID: testAWSARN}, awsImportSource(t))
			require.Error(t, err)
			require.False(t, ready)
			switch mode {
			case "parameters ARN", "import ARN", "public ARN":
				require.ErrorContains(t, err, "mismatch")
			case "public identity":
				require.ErrorContains(t, err, "MISMATCH")
			case "cancelled":
				require.ErrorIs(t, err, context.Canceled)
			}
			if mode == "import ARN" || mode == "public ARN" || mode == "public identity" {
				require.ErrorContains(t, err, "cosmosigner pubkey --backend awskms --aws-key-id "+testAWSARN)
				require.NotContains(t, err.Error(), "resuming")
			}
			if mode == "parameters ARN" || mode == "missing token" || mode == "expired token" || mode == "invalid wrapping key" || mode == "cancelled" {
				require.Zero(t, imports.Load())
			}
		})
	}
}
