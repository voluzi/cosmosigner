package cmd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cmtlog "github.com/cometbft/cometbft/libs/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/voluzi/cosmosigner/internal/backend"
	"github.com/voluzi/cosmosigner/internal/config"
)

const awsCommandARN = "arn:aws:kms:eu-west-2:123456789012:key/12345678-1234-1234-1234-123456789012"

func commandAWSEndpoint(t *testing.T, handler func(string, json.RawMessage) (any, int)) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var input json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			t.Errorf("decode request: %v", err)
			w.WriteHeader(400)
			return
		}
		assert.Contains(t, r.Header.Get("Authorization"), "/eu-west-2/kms/aws4_request")
		body, status := handler(strings.TrimPrefix(r.Header.Get("X-Amz-Target"), "TrentService."), input)
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		w.WriteHeader(status)
		if err := json.NewEncoder(w).Encode(body); err != nil {
			t.Errorf("encode response: %v", err)
		}
	}))
	t.Cleanup(server.Close)
	shared := filepath.Join(t.TempDir(), "empty-aws-config")
	require.NoError(t, os.WriteFile(shared, nil, 0600))
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_CONFIG_FILE", shared)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", shared)
	t.Setenv("AWS_ENDPOINT_URL_KMS", server.URL)
	t.Setenv("AWS_ACCESS_KEY_ID", "test-access-key")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test-secret-key")
	t.Setenv("AWS_SESSION_TOKEN", "")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("COSMOSIGNER_AWS_REGION", "eu-west-1")
	t.Setenv("COSMOSIGNER_AWS_KEY_ID", "")
}

func TestAWSBackendFlagsOverlayEnvironment(t *testing.T) {
	t.Setenv("COSMOSIGNER_BACKEND", "awskms")
	t.Setenv("COSMOSIGNER_AWS_KEY_ID", "alias/from-env")
	t.Setenv("COSMOSIGNER_AWS_REGION", "eu-west-1")
	command := NewPubkeyCmd()
	require.NoError(t, command.ParseFlags([]string{"--aws-key-id", awsCommandARN, "--aws-region", "eu-west-2"}))
	cfg, err := config.LoadBackend(func(c *backend.Config) { overlayBackendFlags(command, c) })
	require.NoError(t, err)
	require.Equal(t, backend.TypeAWSKMS, cfg.Type)
	require.Equal(t, awsCommandARN, cfg.AWSKMS.KeyID)
	require.Equal(t, "eu-west-2", cfg.AWSKMS.Region)
}

func TestProvisionAWSCommand(t *testing.T) {
	commandAWSEndpoint(t, func(op string, raw json.RawMessage) (any, int) {
		assert.Equal(t, "CreateKey", op)
		return map[string]any{"KeyMetadata": map[string]any{"Arn": awsCommandARN, "KeyId": "12345678-1234-1234-1234-123456789012", "KeySpec": "ECC_NIST_EDWARDS25519", "KeyUsage": "SIGN_VERIFY", "KeyManager": "CUSTOMER", "KeyState": "Enabled", "Origin": "AWS_KMS", "MultiRegion": false}}, 200
	})
	var output bytes.Buffer
	command := NewProvisionCmd()
	command.SetOut(&output)
	command.SetArgs([]string{"--backend", "awskms", "--aws-region", "eu-west-2"})
	require.NoError(t, command.Execute())
	require.Contains(t, output.String(), awsCommandARN)
	require.Contains(t, output.String(), "--aws-key-id")
}

func TestImportAWSCommandRecoveryReminder(t *testing.T) {
	wrapping, err := rsa.GenerateKey(rand.Reader, 4096)
	require.NoError(t, err)
	wrappingDER, err := x509.MarshalPKIXPublicKey(&wrapping.PublicKey)
	require.NoError(t, err)
	sourceFile := filepath.Join(t.TempDir(), "priv_validator_key.json")
	writeProvisionTestKey(t, sourceFile)
	_, sourcePub, err := backend.LoadKeyFilePKCS8(sourceFile)
	require.NoError(t, err)
	pubDER, err := x509.MarshalPKIXPublicKey(ed25519.PublicKey(sourcePub.Bytes()))
	require.NoError(t, err)
	for _, mode := range []string{"ready", "deferred", "read denied", "read cancelled"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			commandAWSEndpoint(t, func(op string, raw json.RawMessage) (any, int) {
				switch op {
				case "CreateKey":
					return map[string]any{"KeyMetadata": map[string]any{"Arn": awsCommandARN, "KeyId": "12345678-1234-1234-1234-123456789012", "KeySpec": "ECC_NIST_EDWARDS25519", "KeyUsage": "SIGN_VERIFY", "KeyManager": "CUSTOMER", "KeyState": "PendingImport", "Origin": "EXTERNAL", "MultiRegion": false}}, 200
				case "GetParametersForImport":
					return map[string]any{"KeyId": awsCommandARN, "PublicKey": wrappingDER, "ImportToken": []byte("token"), "ParametersValidTo": float64(time.Now().Add(time.Hour).Unix())}, 200
				case "ImportKeyMaterial":
					return map[string]any{"KeyId": awsCommandARN}, 200
				case "GetPublicKey":
					if mode == "read cancelled" {
						cancel()
						return map[string]any{"__type": "KMSInvalidStateException", "message": "finalizing"}, 400
					}
					if mode == "read denied" {
						return map[string]any{"__type": "AccessDeniedException", "message": "denied"}, 400
					}
					if mode == "deferred" {
						return map[string]any{"__type": "KMSInvalidStateException", "message": "finalizing"}, 400
					}
					return map[string]any{"KeyId": awsCommandARN, "KeySpec": "ECC_NIST_EDWARDS25519", "KeyUsage": "SIGN_VERIFY", "SigningAlgorithms": []string{"ED25519_SHA_512"}, "PublicKey": pubDER}, 200
				default:
					t.Errorf("unexpected operation %s", op)
					return map[string]any{}, 400
				}
			})
			var output bytes.Buffer
			command := NewImportCmd()
			command.SetContext(ctx)
			command.SetOut(&output)
			command.SetArgs([]string{"--backend", "awskms", "--aws-region", "eu-west-2", "--from", sourceFile})
			require.NoError(t, command.Execute())
			require.Contains(t, output.String(), awsCommandARN)
			require.Contains(t, output.String(), "protected recovery backup")
			require.NotContains(t, output.String(), "destroy all copies")
			if mode == "ready" {
				require.Contains(t, output.String(), "verified: backend public key matches")
			} else {
				require.Contains(t, output.String(), "identity not verified yet")
				require.Contains(t, output.String(), "cosmosigner pubkey --backend awskms --aws-key-id "+awsCommandARN)
				require.NotContains(t, output.String(), "destroy the source key file")
			}
		})
	}
}

func TestAWSClaimStartupWarning(t *testing.T) {
	be := &claimingBackend{}
	var logs bytes.Buffer
	err := claimWithConfig(backend.Config{Type: backend.TypeAWSKMS}, be, false, cmtlog.NewTMLogger(&logs))(t.Context(), startTestClusterID)
	require.NoError(t, err)
	require.Len(t, be.claims, 1)
	require.Contains(t, logs.String(), "eventually consistent")
	require.Contains(t, logs.String(), "compare-and-set")
	require.Contains(t, logs.String(), "serialize")
}

func TestAWSImportPartialFailureReportsRecoveryTarget(t *testing.T) {
	for _, mode := range []string{"missing token", "invalid wrapping key", "wrong parameters ARN", "created metadata"} {
		t.Run(mode, func(t *testing.T) {
			sourceFile := filepath.Join(t.TempDir(), "priv_validator_key.json")
			writeProvisionTestKey(t, sourceFile)
			commandAWSEndpoint(t, func(op string, raw json.RawMessage) (any, int) {
				switch op {
				case "CreateKey":
					spec := "ECC_NIST_EDWARDS25519"
					if mode == "created metadata" {
						spec = "RSA_4096"
					}
					return map[string]any{"KeyMetadata": map[string]any{"Arn": awsCommandARN, "KeyId": "12345678-1234-1234-1234-123456789012", "KeySpec": spec, "KeyUsage": "SIGN_VERIFY", "KeyManager": "CUSTOMER", "KeyState": "PendingImport", "Origin": "EXTERNAL", "MultiRegion": false}}, 200
				case "GetParametersForImport":
					response := map[string]any{"KeyId": awsCommandARN, "ImportToken": []byte("token"), "PublicKey": []byte{1, 2}, "ParametersValidTo": float64(time.Now().Add(time.Hour).Unix())}
					if mode == "missing token" {
						delete(response, "ImportToken")
					}
					if mode == "wrong parameters ARN" {
						response["KeyId"] = "arn:aws:kms:eu-west-2:123456789012:key/87654321-1234-1234-1234-123456789012"
					}
					return response, 200
				default:
					t.Errorf("unexpected operation after partial failure: %s", op)
					return map[string]any{}, 400
				}
			})
			var output bytes.Buffer
			command := NewImportCmd()
			command.SetErr(&output)
			command.SetOut(&output)
			command.SetArgs([]string{"--backend", "awskms", "--aws-region", "eu-west-2", "--from", sourceFile})
			err := command.Execute()
			require.Error(t, err)
			require.ErrorContains(t, err, "--aws-key-id "+awsCommandARN)
			require.Contains(t, output.String(), awsCommandARN)
		})
	}
}
