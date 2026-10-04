package backend

import (
	"encoding/json"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func awsMetadata(origin, state string) map[string]any {
	return map[string]any{"Arn": testAWSARN, "KeyId": "12345678-1234-1234-1234-123456789012", "KeySpec": "ECC_NIST_EDWARDS25519", "KeyUsage": "SIGN_VERIFY", "KeyManager": "CUSTOMER", "Origin": origin, "KeyState": state, "MultiRegion": false}
}

func TestAWSKMSProvision(t *testing.T) {
	for _, tc := range []struct {
		name, wantError string
		mutate          func(map[string]any)
	}{
		{name: "single Region Ed25519"},
		{name: "multi Region", wantError: "multi-Region", mutate: func(m map[string]any) { m["MultiRegion"] = true }},
		{name: "wrong origin", wantError: "metadata", mutate: func(m map[string]any) { m["Origin"] = "EXTERNAL" }},
		{name: "wrong spec", wantError: "metadata", mutate: func(m map[string]any) { m["KeySpec"] = "RSA_4096" }},
		{name: "malformed ARN", wantError: "ARN", mutate: func(m map[string]any) { m["Arn"] = "key-id" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			metadata := awsMetadata("AWS_KMS", "Enabled")
			if tc.mutate != nil {
				tc.mutate(metadata)
			}
			awsTestServer(t, func(op string, raw json.RawMessage) (any, int) {
				assert.Equal(t, "CreateKey", op)
				var req struct {
					KeySpec, KeyUsage, Origin string
					MultiRegion               bool
				}
				assert.NoError(t, json.Unmarshal(raw, &req))
				assert.Equal(t, "ECC_NIST_EDWARDS25519", req.KeySpec)
				assert.Equal(t, "SIGN_VERIFY", req.KeyUsage)
				assert.Equal(t, "AWS_KMS", req.Origin)
				assert.False(t, req.MultiRegion)
				return map[string]any{"KeyMetadata": metadata}, 200
			})
			got, err := AWSProvisionKey(t.Context(), AWSKMSConfig{})
			if tc.wantError != "" {
				require.ErrorContains(t, err, tc.wantError)
			} else {
				require.NoError(t, err)
				require.Equal(t, testAWSARN, got)
			}
		})
	}
}

func TestAWSKMSCreateKeyIsNeverRetried(t *testing.T) {
	for _, mode := range []string{"provision", "import"} {
		t.Run(mode, func(t *testing.T) {
			var creates atomic.Int32
			awsTestServer(t, func(op string, raw json.RawMessage) (any, int) {
				assert.Equal(t, "CreateKey", op)
				creates.Add(1)
				return map[string]any{"__type": "KMSInternalException", "message": "ambiguous server error"}, 500
			})
			if mode == "provision" {
				_, err := AWSProvisionKey(t.Context(), AWSKMSConfig{})
				require.Error(t, err)
			} else {
				key := awsImportSource(t)
				_, _, err := AWSImportKey(t.Context(), AWSKMSConfig{}, key)
				require.Error(t, err)
			}
			require.EqualValues(t, 1, creates.Load())
		})
	}
}
