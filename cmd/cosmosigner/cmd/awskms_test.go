package cmd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	cmted25519 "github.com/cometbft/cometbft/crypto/ed25519"
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
	commandAWSConfig(t, server.URL)
}

func commandAWSConfig(t *testing.T, endpoint string) {
	t.Helper()
	shared := filepath.Join(t.TempDir(), "empty-aws-config")
	require.NoError(t, os.WriteFile(shared, nil, 0600))
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_CONFIG_FILE", shared)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", shared)
	t.Setenv("AWS_ENDPOINT_URL_KMS", endpoint)
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
	for _, mode := range []string{"ready", "enabled", "deferred", "read denied", "read cancelled"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			commandAWSEndpoint(t, func(op string, raw json.RawMessage) (any, int) {
				switch op {
				case "DescribeKey":
					return map[string]any{"KeyMetadata": map[string]any{"Arn": awsCommandARN, "KeyId": "12345678-1234-1234-1234-123456789012", "KeySpec": "ECC_NIST_EDWARDS25519", "KeyUsage": "SIGN_VERIFY", "KeyManager": "CUSTOMER", "KeyState": "Enabled", "Origin": "EXTERNAL", "MultiRegion": false}}, 200
				case "ListResourceTags":
					return map[string]any{}, 200
				case "CreateKey":
					assert.NotEqual(t, "enabled", mode)
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
			args := []string{"--backend", "awskms", "--aws-region", "eu-west-2", "--from", sourceFile}
			if mode == "enabled" {
				args = append(args, "--aws-key-id", "alias/validator")
			}
			command.SetArgs(args)
			require.NoError(t, command.Execute())
			require.Contains(t, output.String(), "imported key version: "+awsCommandARN+"\n")
			require.Contains(t, output.String(), "protected recovery backup")
			require.NotContains(t, output.String(), "destroy all copies")
			if mode == "ready" || mode == "enabled" {
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
	for _, level := range []string{"info", "warn", "error"} {
		t.Run(level, func(t *testing.T) {
			read, write, err := os.Pipe()
			require.NoError(t, err)
			stderr := os.Stderr
			os.Stderr = write
			t.Cleanup(func() {
				os.Stderr = stderr
				_ = write.Close()
				_ = read.Close()
			})
			be := &claimingBackend{}
			require.NoError(t, claimWithConfig(backend.Config{Type: backend.TypeAWSKMS}, be, false, newCmtLogger(level))(t.Context(), startTestClusterID))
			require.NoError(t, write.Close())
			warning, err := io.ReadAll(read)
			require.NoError(t, err)
			require.Len(t, be.claims, 1)
			require.Contains(t, string(warning), "eventually consistent")
			require.Contains(t, string(warning), "compare-and-set")
			require.Contains(t, string(warning), "serialize")
		})
	}
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

func TestPubkeyAWSCommandPrintsResolvedARN(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	der, err := x509.MarshalPKIXPublicKey(key.Public())
	require.NoError(t, err)
	commandAWSEndpoint(t, func(op string, raw json.RawMessage) (any, int) {
		assert.Equal(t, "GetPublicKey", op)
		var req struct{ KeyId string }
		assert.NoError(t, json.Unmarshal(raw, &req))
		assert.Equal(t, "alias/validator", req.KeyId)
		return map[string]any{"KeyId": awsCommandARN, "KeySpec": "ECC_NIST_EDWARDS25519", "KeyUsage": "SIGN_VERIFY", "SigningAlgorithms": []string{"ED25519_SHA_512"}, "PublicKey": der}, 200
	})
	var output bytes.Buffer
	command := NewPubkeyCmd()
	command.SetOut(&output)
	command.SetArgs([]string{"--backend", "awskms", "--aws-region", "eu-west-2", "--aws-key-id", "alias/validator"})
	require.NoError(t, command.Execute())
	pub := cmted25519.PubKey(key.Public().(ed25519.PublicKey))
	require.Equal(t, "aws key arn:    "+awsCommandARN+"\naddress:        "+pub.Address().String()+"\npubkey (base64): "+base64.StdEncoding.EncodeToString(pub)+"\n", output.String())
}

func TestAWSClaimRoleAssumedOnlyForClaim(t *testing.T) {
	const roleARN = "arn:aws:iam::123456789012:role/claim"
	for _, mode := range []string{"startup role", "startup caller", "standalone caller"} {
		t.Run(mode, func(t *testing.T) {
			var assumes, tags, signs, runtimeReads atomic.Int32
			var claiming, claimed atomic.Bool
			stsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assumes.Add(1)
				assert.NoError(t, r.ParseForm())
				assert.Equal(t, "AssumeRole", r.Form.Get("Action"))
				assert.Equal(t, roleARN, r.Form.Get("RoleArn"))
				assert.Contains(t, r.Header.Get("Authorization"), "Credential=test-access-key/")
				w.Header().Set("Content-Type", "text/xml")
				_, err := fmt.Fprintf(w, `<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult><Credentials><AccessKeyId>assumed-access-key</AccessKeyId><SecretAccessKey>assumed-secret-key</SecretAccessKey><SessionToken>claim-session-token</SessionToken><Expiration>%s</Expiration></Credentials><AssumedRoleUser><Arn>arn:aws:sts::123456789012:assumed-role/claim/test</Arn><AssumedRoleId>claim:test</AssumedRoleId></AssumedRoleUser></AssumeRoleResult></AssumeRoleResponse>`, time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
				assert.NoError(t, err)
			}))
			t.Cleanup(stsServer.Close)
			key := ed25519.NewKeyFromSeed(make([]byte, 32))
			der, err := x509.MarshalPKIXPublicKey(key.Public())
			require.NoError(t, err)
			kmsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var req struct {
					KeyId   string
					Message []byte
					Tags    []struct{ TagKey, TagValue string }
				}
				assert.NoError(t, json.NewDecoder(r.Body).Decode(&req))
				assert.Equal(t, awsCommandARN, req.KeyId)
				accessKey, token := "test-access-key", ""
				if claiming.Load() && mode == "startup role" {
					accessKey, token = "assumed-access-key", "claim-session-token"
				}
				assert.Contains(t, r.Header.Get("Authorization"), "Credential="+accessKey+"/")
				assert.Equal(t, token, r.Header.Get("X-Amz-Security-Token"))
				var body any
				switch op := strings.TrimPrefix(r.Header.Get("X-Amz-Target"), "TrentService."); op {
				case "GetPublicKey":
					if !claiming.Load() {
						runtimeReads.Add(1)
					}
					body = map[string]any{"KeyId": awsCommandARN, "KeySpec": "ECC_NIST_EDWARDS25519", "KeyUsage": "SIGN_VERIFY", "SigningAlgorithms": []string{"ED25519_SHA_512"}, "PublicKey": der}
				case "ListResourceTags":
					if !claiming.Load() {
						runtimeReads.Add(1)
					}
					body = map[string]any{}
					if claimed.Load() {
						body = map[string]any{"Tags": []map[string]string{{"TagKey": "cosmosigner-cluster-id", "TagValue": startTestClusterID}}}
					}
				case "TagResource":
					tags.Add(1)
					assert.Equal(t, []struct{ TagKey, TagValue string }{{"cosmosigner-cluster-id", startTestClusterID}}, req.Tags)
					claimed.Store(true)
					body = map[string]any{}
				case "Sign":
					signs.Add(1)
					body = map[string]any{"KeyId": awsCommandARN, "SigningAlgorithm": "ED25519_SHA_512", "Signature": ed25519.Sign(key, req.Message)}
				default:
					t.Errorf("unexpected AWS call %s", op)
					w.WriteHeader(400)
					return
				}
				w.Header().Set("Content-Type", "application/x-amz-json-1.1")
				assert.NoError(t, json.NewEncoder(w).Encode(body))
			}))
			t.Cleanup(kmsServer.Close)
			commandAWSConfig(t, kmsServer.URL)
			t.Setenv("AWS_ENDPOINT_URL_STS", stsServer.URL)
			cfg := backend.Config{Type: backend.TypeAWSKMS, AWSKMS: backend.AWSKMSConfig{KeyID: awsCommandARN, Region: "eu-west-2"}}
			if mode != "startup caller" {
				cfg.AWSKMS.ClaimRoleARN = roleARN
			}
			be, err := backend.New(cfg)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, be.Close()) })
			claiming.Store(true)
			if mode == "standalone caller" {
				t.Setenv("COSMOSIGNER_AWS_CLAIM_ROLE_ARN", roleARN)
				command := NewClaimKeyCmd()
				command.SetOut(io.Discard)
				command.SetErr(io.Discard)
				command.SetArgs([]string{"--backend", "awskms", "--aws-key-id", awsCommandARN, "--aws-region", "eu-west-2", "--cluster-id", startTestClusterID})
				require.NoError(t, command.Execute())
			} else {
				require.NoError(t, claimWithConfig(backend.ClaimConfig(cfg), be, backend.HasSeparateClaimCredentials(cfg), newCmtLogger("error"))(t.Context(), startTestClusterID))
			}
			claiming.Store(false)
			require.NoError(t, backend.RequireClusterBinding(t.Context(), be, startTestClusterID))
			message := []byte("runtime message after claim")
			signature, err := be.Sign(message)
			require.NoError(t, err)
			require.True(t, ed25519.Verify(key.Public().(ed25519.PublicKey), message, signature))
			require.EqualValues(t, 1, tags.Load())
			require.EqualValues(t, 1, signs.Load())
			require.EqualValues(t, 2, runtimeReads.Load())
			if mode == "startup role" {
				require.EqualValues(t, 1, assumes.Load())
			} else {
				require.Zero(t, assumes.Load())
			}
		})
	}
}
