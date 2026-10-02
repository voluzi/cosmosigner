package backend

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	voied25519 "github.com/oasisprotocol/curve25519-voi/primitives/ed25519"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testAWSARN = "arn:aws:kms:eu-west-1:123456789012:key/12345678-1234-1234-1234-123456789012"
const otherAWSARN = "arn:aws:kms:eu-west-1:123456789012:key/87654321-1234-1234-1234-123456789012"

type awsRequest struct {
	KeyID            string `json:"KeyId"`
	Message          []byte
	MessageType      string
	SigningAlgorithm string
	Marker           *string
	Tags             []struct{ TagKey, TagValue string }
}

type awsHTTPHandler func(string, json.RawMessage) (any, int)

func awsTestServer(t *testing.T, handler awsHTTPHandler) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var input json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			t.Errorf("decode AWS request: %v", err)
			w.WriteHeader(400)
			return
		}
		operation := strings.TrimPrefix(r.Header.Get("X-Amz-Target"), "TrentService.")
		body, status := handler(operation, input)
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		w.WriteHeader(status)
		if err := json.NewEncoder(w).Encode(body); err != nil {
			t.Errorf("encode AWS response: %v", err)
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
	t.Setenv("AWS_REGION", "eu-west-1")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
}

func awsPublicResponse(t *testing.T, key ed25519.PrivateKey) map[string]any {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key.Public())
	require.NoError(t, err)
	return map[string]any{"KeyId": testAWSARN, "KeySpec": "ECC_NIST_EDWARDS25519", "KeyUsage": "SIGN_VERIFY", "SigningAlgorithms": []string{"ED25519_SHA_512"}, "PublicKey": der}
}

func newAWSTestBackend(t *testing.T, keyID string) KeyBackend {
	t.Helper()
	b, err := New(Config{Type: TypeAWSKMS, AWSKMS: AWSKMSConfig{KeyID: keyID, Timeout: time.Second}})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, b.Close()) })
	return b
}

func TestAWSKMSConstruction(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	for _, tc := range []struct {
		name, keyID, wantError string
		mutate                 func(map[string]any)
	}{
		{name: "alias", keyID: "alias/validator"},
		{name: "alias ARN", keyID: "arn:aws:kms:eu-west-1:123456789012:alias/validator"},
		{name: "wrong spec", keyID: testAWSARN, wantError: "key spec", mutate: func(m map[string]any) { m["KeySpec"] = "ECC_NIST_P256" }},
		{name: "wrong usage", keyID: testAWSARN, wantError: "key usage", mutate: func(m map[string]any) { m["KeyUsage"] = "ENCRYPT_DECRYPT" }},
		{name: "prehashed only", keyID: testAWSARN, wantError: "ED25519_SHA_512", mutate: func(m map[string]any) { m["SigningAlgorithms"] = []string{"ED25519_PH_SHA_512"} }},
		{name: "malformed SPKI", keyID: testAWSARN, wantError: "public key", mutate: func(m map[string]any) { m["PublicKey"] = []byte{1, 2, 3} }},
		{name: "wrong ASN1 type", keyID: testAWSARN, wantError: "ed25519", mutate: func(m map[string]any) {
			m["PublicKey"] = []byte{0x30, 0x2a, 0x30, 5, 6, 3, 0x2b, 0x65, 0x6e, 3, 0x21, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
		}},
		{name: "ARN mismatch", keyID: testAWSARN, wantError: "mismatch", mutate: func(m map[string]any) { m["KeyId"] = otherAWSARN }},
		{name: "bad ARN", keyID: "alias/validator", wantError: "ARN", mutate: func(m map[string]any) { m["KeyId"] = "alias/validator" }},
		{name: "multi Region", keyID: "alias/validator", wantError: "multi-Region", mutate: func(m map[string]any) {
			m["KeyId"] = "arn:aws:kms:eu-west-1:123456789012:key/mrk-12345678901234567890123456789012"
		}},
		{name: "empty key ID", wantError: "key ID"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := awsPublicResponse(t, key)
			if tc.mutate != nil {
				tc.mutate(response)
			}
			awsTestServer(t, func(op string, raw json.RawMessage) (any, int) {
				assert.Equal(t, "GetPublicKey", op)
				var req awsRequest
				assert.NoError(t, json.Unmarshal(raw, &req))
				assert.Equal(t, tc.keyID, req.KeyID)
				return response, 200
			})
			b, err := New(Config{Type: TypeAWSKMS, AWSKMS: AWSKMSConfig{KeyID: tc.keyID}})
			if tc.wantError != "" {
				require.ErrorContains(t, err, tc.wantError)
				return
			}
			require.NoError(t, err)
			defer b.Close()
			pub, err := b.PubKey()
			require.NoError(t, err)
			require.Equal(t, []byte(key.Public().(ed25519.PublicKey)), pub.Bytes())
		})
	}
}

func TestAWSKMSSignResponseIntegrity(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	for _, tc := range []struct {
		name, wantError string
		length          int
		mutate          func(map[string]any)
	}{
		{name: "minimum", length: 1}, {name: "maximum", length: 4096},
		{name: "empty", length: 0, wantError: "1..4096"}, {name: "too large", length: 4097, wantError: "1..4096"},
		{name: "wrong key", length: 10, wantError: "mismatch", mutate: func(m map[string]any) { m["KeyId"] = otherAWSARN }},
		{name: "prehashed", length: 10, wantError: "algorithm", mutate: func(m map[string]any) { m["SigningAlgorithm"] = "ED25519_PH_SHA_512" }},
		{name: "short", length: 10, wantError: "signature size", mutate: func(m map[string]any) { m["Signature"] = make([]byte, 63) }},
		{name: "long", length: 10, wantError: "signature size", mutate: func(m map[string]any) { m["Signature"] = make([]byte, 65) }},
		{name: "foreign signature", length: 10, wantError: "verify", mutate: func(m map[string]any) { m["Signature"] = make([]byte, 64) }},
		{name: "empty response", length: 10, wantError: "mismatch", mutate: func(m map[string]any) { clear(m) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pubResponse := awsPublicResponse(t, key)
			message := make([]byte, tc.length)
			var signs atomic.Int32
			awsTestServer(t, func(op string, raw json.RawMessage) (any, int) {
				if op == "GetPublicKey" {
					return pubResponse, 200
				}
				assert.Equal(t, "Sign", op)
				signs.Add(1)
				var req awsRequest
				assert.NoError(t, json.Unmarshal(raw, &req))
				assert.Equal(t, testAWSARN, req.KeyID)
				assert.Equal(t, "RAW", req.MessageType)
				assert.Equal(t, "ED25519_SHA_512", req.SigningAlgorithm)
				assert.Equal(t, message, req.Message)
				response := map[string]any{"KeyId": testAWSARN, "SigningAlgorithm": "ED25519_SHA_512", "Signature": ed25519.Sign(key, req.Message)}
				if tc.mutate != nil {
					tc.mutate(response)
				}
				return response, 200
			})
			b := newAWSTestBackend(t, "alias/validator")
			sig, err := b.Sign(message)
			if tc.wantError != "" {
				require.ErrorContains(t, err, tc.wantError)
				require.Nil(t, sig)
			} else {
				require.NoError(t, err)
				require.Equal(t, ed25519.Sign(key, message), sig)
			}
			if tc.length == 0 || tc.length > 4096 {
				require.Zero(t, signs.Load())
			}
		})
	}
}

func TestAWSKMSSignDeterminism(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	pubResponse := awsPublicResponse(t, key)
	awsTestServer(t, func(op string, raw json.RawMessage) (any, int) {
		if op == "GetPublicKey" {
			return pubResponse, 200
		}
		var req awsRequest
		assert.NoError(t, json.Unmarshal(raw, &req))
		return map[string]any{"KeyId": testAWSARN, "SigningAlgorithm": "ED25519_SHA_512", "Signature": ed25519.Sign(key, req.Message)}, 200
	})
	first := newAWSTestBackend(t, testAWSARN)
	second := newAWSTestBackend(t, testAWSARN)
	requireSignDeterminism(t, first, second)
}

func TestAWSKMSPreflight(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	for _, mode := range []string{"deterministic", "randomized", "denied", "invalid"} {
		t.Run(mode, func(t *testing.T) {
			pubResponse := awsPublicResponse(t, key)
			var signs atomic.Int32
			awsTestServer(t, func(op string, raw json.RawMessage) (any, int) {
				if op == "GetPublicKey" {
					return pubResponse, 200
				}
				signs.Add(1)
				var req awsRequest
				assert.NoError(t, json.Unmarshal(raw, &req))
				assert.Contains(t, string(req.Message), "not a consensus message")
				if mode == "denied" {
					return map[string]any{"__type": "AccessDeniedException", "message": "denied"}, 400
				}
				sig := ed25519.Sign(key, req.Message)
				if mode == "randomized" {
					var err error
					sig, err = voied25519.PrivateKey(key).Sign(rand.Reader, req.Message, &voied25519.Options{AddedRandomness: true})
					assert.NoError(t, err)
					assert.True(t, ed25519.Verify(key.Public().(ed25519.PublicKey), req.Message, sig))
				}
				if mode == "invalid" {
					sig = make([]byte, 64)
				}
				return map[string]any{"KeyId": testAWSARN, "SigningAlgorithm": "ED25519_SHA_512", "Signature": sig}, 200
			})
			b := newAWSTestBackend(t, testAWSARN)
			preflight, ok := b.(interface{ VerifyCanSign(context.Context) error })
			require.True(t, ok)
			err := preflight.VerifyCanSign(t.Context())
			switch mode {
			case "deterministic":
				require.NoError(t, err)
				require.EqualValues(t, 2, signs.Load())
			case "randomized":
				require.ErrorContains(t, err, "non-deterministic")
				require.EqualValues(t, 2, signs.Load())
			default:
				require.Error(t, err)
			}
		})
	}
}

func TestAWSKMSPreflightCancellation(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	pubResponse := awsPublicResponse(t, key)
	entered := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	awsTestServer(t, func(op string, raw json.RawMessage) (any, int) {
		if op == "GetPublicKey" {
			return pubResponse, 200
		}
		close(entered)
		<-release
		return map[string]any{}, 200
	})
	b := newAWSTestBackend(t, testAWSARN)
	preflight, ok := b.(interface{ VerifyCanSign(context.Context) error })
	require.True(t, ok)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- preflight.VerifyCanSign(ctx) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("sign did not start")
	}
	cancel()
	select {
	case err := <-result:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("sign ignored cancellation")
	}
}
