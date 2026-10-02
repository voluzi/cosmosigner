package backend

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/voluzi/cosmosigner/internal/clusterid"
)

func TestAWSKMSBindingReadsAllPages(t *testing.T) {
	id, err := clusterid.New()
	require.NoError(t, err)
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	pubResponse := awsPublicResponse(t, key)
	for _, tc := range []struct {
		name      string
		page      map[string]any
		wantError error
	}{
		{name: "found on second page", page: map[string]any{"Tags": []map[string]string{{"TagKey": "cosmosigner-cluster-id", "TagValue": id}}}},
		{name: "missing", page: map[string]any{}, wantError: ErrBindingUnclaimed},
		{name: "corrupt", page: map[string]any{"Tags": []map[string]string{{"TagKey": "cosmosigner-cluster-id", "TagValue": "bad"}}}, wantError: ErrBindingCorrupt},
		{name: "missing marker", page: map[string]any{"Truncated": true}, wantError: ErrBindingUnreadable},
		{name: "repeated marker", page: map[string]any{"Truncated": true, "NextMarker": "page-2"}, wantError: ErrBindingUnreadable},
		{name: "duplicate claim", page: map[string]any{"Tags": []map[string]string{{"TagKey": "cosmosigner-cluster-id", "TagValue": id}, {"TagKey": "cosmosigner-cluster-id", "TagValue": id}}}, wantError: ErrBindingCorrupt},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var reads atomic.Int32
			awsTestServer(t, func(op string, raw json.RawMessage) (any, int) {
				if op == "GetPublicKey" {
					return pubResponse, 200
				}
				assert.Equal(t, "ListResourceTags", op)
				var req awsRequest
				assert.NoError(t, json.Unmarshal(raw, &req))
				assert.Equal(t, testAWSARN, req.KeyID)
				if reads.Add(1) == 1 {
					assert.Nil(t, req.Marker)
					return map[string]any{"Tags": []map[string]string{{"TagKey": "unrelated", "TagValue": "keep"}}, "Truncated": true, "NextMarker": "page-2"}, 200
				}
				assert.NotNil(t, req.Marker)
				if req.Marker != nil {
					assert.Equal(t, "page-2", *req.Marker)
				}
				return tc.page, 200
			})
			b := newAWSTestBackend(t, "alias/validator")
			got, err := b.ClusterBinding(t.Context())
			if tc.wantError != nil {
				require.ErrorIs(t, err, tc.wantError)
			} else {
				require.NoError(t, err)
				require.Equal(t, id, got)
			}
			require.EqualValues(t, 2, reads.Load())
		})
	}
}

func TestAWSKMSClaimFailClosed(t *testing.T) {
	id, err := clusterid.New()
	require.NoError(t, err)
	other, err := clusterid.New()
	require.NoError(t, err)
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	pubResponse := awsPublicResponse(t, key)
	for _, tc := range []struct {
		name, existing string
		wantError      error
		denied         bool
	}{
		{name: "same owner", existing: id},
		{name: "different owner", existing: other, wantError: ErrBindingMismatch},
		{name: "corrupt", existing: "corrupt", wantError: ErrBindingCorrupt},
		{name: "unreadable", denied: true, wantError: ErrBindingUnreadable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var writes atomic.Int32
			awsTestServer(t, func(op string, raw json.RawMessage) (any, int) {
				if op == "GetPublicKey" {
					return pubResponse, 200
				}
				if op == "TagResource" {
					writes.Add(1)
					return map[string]any{}, 200
				}
				assert.Equal(t, "ListResourceTags", op)
				if tc.denied {
					return map[string]any{"__type": "AccessDeniedException", "message": "denied"}, 400
				}
				return map[string]any{"Tags": []map[string]string{{"TagKey": "cosmosigner-cluster-id", "TagValue": tc.existing}}}, 200
			})
			b := newAWSTestBackend(t, testAWSARN)
			err := b.ClaimCluster(t.Context(), id)
			if tc.wantError != nil {
				require.ErrorIs(t, err, tc.wantError)
			} else {
				require.NoError(t, err)
			}
			require.Zero(t, writes.Load())
		})
	}
}

func TestAWSKMSClaimReadback(t *testing.T) {
	id, err := clusterid.New()
	require.NoError(t, err)
	other, err := clusterid.New()
	require.NoError(t, err)
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	pubResponse := awsPublicResponse(t, key)
	for _, mode := range []string{"delayed", "different owner", "write denied", "read denied", "never visible"} {
		t.Run(mode, func(t *testing.T) {
			var writes, reads atomic.Int32
			awsTestServer(t, func(op string, raw json.RawMessage) (any, int) {
				if op == "GetPublicKey" {
					return pubResponse, 200
				}
				if op == "TagResource" {
					writes.Add(1)
					var req awsRequest
					assert.NoError(t, json.Unmarshal(raw, &req))
					assert.Equal(t, testAWSARN, req.KeyID)
					assert.Len(t, req.Tags, 1)
					if len(req.Tags) == 1 {
						assert.Equal(t, "cosmosigner-cluster-id", req.Tags[0].TagKey)
						assert.Equal(t, id, req.Tags[0].TagValue)
					}
					if mode == "write denied" {
						return map[string]any{"__type": "AccessDeniedException", "message": "denied"}, 400
					}
					return map[string]any{}, 200
				}
				assert.Equal(t, "ListResourceTags", op)
				reads.Add(1)
				if writes.Load() == 0 || mode == "never visible" || mode == "delayed" && reads.Load() < 3 {
					return map[string]any{}, 200
				}
				if mode == "read denied" {
					return map[string]any{"__type": "AccessDeniedException", "message": "denied"}, 400
				}
				value := id
				if mode == "different owner" {
					value = other
				}
				return map[string]any{"Tags": []map[string]string{{"TagKey": "cosmosigner-cluster-id", "TagValue": value}}}, 200
			})
			b := newAWSTestBackend(t, testAWSARN)
			ctx, cancel := context.WithTimeout(t.Context(), 600*time.Millisecond)
			defer cancel()
			err := b.ClaimCluster(ctx, id)
			switch mode {
			case "delayed":
				require.NoError(t, err)
				require.EqualValues(t, 3, reads.Load())
			case "different owner":
				require.ErrorIs(t, err, ErrBindingMismatch)
			case "never visible":
				require.ErrorIs(t, err, context.DeadlineExceeded)
			default:
				require.Error(t, err)
			}
			require.EqualValues(t, 1, writes.Load())
		})
	}
}

func TestAWSKMSClaimCancellation(t *testing.T) {
	id, err := clusterid.New()
	require.NoError(t, err)
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	pubResponse := awsPublicResponse(t, key)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var writes atomic.Int32
	awsTestServer(t, func(op string, raw json.RawMessage) (any, int) {
		if op == "GetPublicKey" {
			return pubResponse, 200
		}
		if op == "TagResource" {
			writes.Add(1)
			cancel()
		}
		return map[string]any{}, 200
	})
	b := newAWSTestBackend(t, testAWSARN)
	require.ErrorIs(t, b.ClaimCluster(ctx, id), context.Canceled)
	require.EqualValues(t, 1, writes.Load())
}
