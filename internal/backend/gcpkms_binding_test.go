package backend

import (
	"context"
	"errors"
	"testing"
	"time"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/googleapis/gax-go/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

const testGCPKeyVersion = "projects/p/locations/global/keyRings/r/cryptoKeys/validator/cryptoKeyVersions/7"

type fakeKMSClient struct {
	key       *kmspb.CryptoKey
	getErr    error
	getErrOn  int
	updateErr error
	gets      int
	updates   int
	request   *kmspb.UpdateCryptoKeyRequest
	lastGet   *kmspb.GetCryptoKeyRequest
	sign      func(context.Context, *kmspb.AsymmetricSignRequest) (*kmspb.AsymmetricSignResponse, error)
}

func (f *fakeKMSClient) GetCryptoKey(_ context.Context, req *kmspb.GetCryptoKeyRequest, _ ...gax.CallOption) (*kmspb.CryptoKey, error) {
	f.gets++
	f.lastGet = proto.Clone(req).(*kmspb.GetCryptoKeyRequest)
	if f.getErr != nil && (f.getErrOn == 0 || f.getErrOn == f.gets) {
		return nil, f.getErr
	}
	return proto.Clone(f.key).(*kmspb.CryptoKey), nil
}

func (f *fakeKMSClient) UpdateCryptoKey(_ context.Context, req *kmspb.UpdateCryptoKeyRequest, _ ...gax.CallOption) (*kmspb.CryptoKey, error) {
	f.updates++
	f.request = proto.Clone(req).(*kmspb.UpdateCryptoKeyRequest)
	if f.updateErr != nil {
		return nil, f.updateErr
	}
	f.key.Labels = req.CryptoKey.Labels
	return proto.Clone(f.key).(*kmspb.CryptoKey), nil
}

func (f *fakeKMSClient) GetPublicKey(context.Context, *kmspb.GetPublicKeyRequest, ...gax.CallOption) (*kmspb.PublicKey, error) {
	return nil, errors.New("unexpected GetPublicKey")
}

func (f *fakeKMSClient) AsymmetricSign(ctx context.Context, req *kmspb.AsymmetricSignRequest, _ ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error) {
	if f.sign != nil {
		return f.sign(ctx, req)
	}
	return nil, errors.New("unexpected AsymmetricSign")
}

func (f *fakeKMSClient) Close() error { return nil }

func newBindingTestGCP(t *testing.T, client *fakeKMSClient) *GCPKMS {
	t.Helper()
	parent, err := gcpCryptoKeyName(testGCPKeyVersion)
	require.NoError(t, err)
	return &GCPKMS{client: client, keyVersion: testGCPKeyVersion, keyResource: parent, timeout: time.Second}
}

func TestGCPBindingClaimsParentKeyAndPreservesLabels(t *testing.T) {
	client := &fakeKMSClient{key: &kmspb.CryptoKey{
		Name:   "projects/p/locations/global/keyRings/r/cryptoKeys/validator",
		Labels: map[string]string{"environment": "production"},
	}}
	g := newBindingTestGCP(t, client)

	_, err := g.ClusterBinding(t.Context())
	require.ErrorIs(t, err, ErrBindingUnclaimed)
	require.Zero(t, client.updates, "runtime read must not claim")
	require.Equal(t, "projects/p/locations/global/keyRings/r/cryptoKeys/validator", client.lastGet.Name)
	require.NoError(t, g.ClaimCluster(t.Context(), clusterA))
	require.Equal(t, 1, client.updates)
	require.Equal(t, []string{"labels"}, client.request.UpdateMask.Paths)
	require.Equal(t, "production", client.request.CryptoKey.Labels["environment"])
	require.Equal(t, clusterA, client.request.CryptoKey.Labels[gcpClusterIDLabel])
	require.Equal(t, client.key.Name, client.request.CryptoKey.Name)

	require.NoError(t, g.ClaimCluster(t.Context(), clusterA))
	require.Equal(t, 1, client.updates, "same-owner retry must not update labels")
	require.ErrorIs(t, g.ClaimCluster(t.Context(), clusterB), ErrBindingMismatch)
	require.Equal(t, 1, client.updates)
}

func TestGCPBindingRejectsMalformedStoredLabel(t *testing.T) {
	client := &fakeKMSClient{key: &kmspb.CryptoKey{
		Name:   "projects/p/locations/global/keyRings/r/cryptoKeys/validator",
		Labels: map[string]string{gcpClusterIDLabel: "not-a-uuid"},
	}}
	g := newBindingTestGCP(t, client)
	_, err := g.ClusterBinding(t.Context())
	require.ErrorIs(t, err, ErrBindingCorrupt)
	require.ErrorIs(t, g.ClaimCluster(t.Context(), clusterA), ErrBindingCorrupt)
	require.Zero(t, client.updates)
}

func TestGCPBindingUpdateFailureDoesNotReportSuccess(t *testing.T) {
	client := &fakeKMSClient{
		key:       &kmspb.CryptoKey{Name: "projects/p/locations/global/keyRings/r/cryptoKeys/validator"},
		updateErr: errors.New("permission denied"),
	}
	g := newBindingTestGCP(t, client)
	require.ErrorContains(t, g.ClaimCluster(t.Context(), clusterA), "permission denied")
}

func TestGCPBindingReadbackFailureDoesNotReportSuccess(t *testing.T) {
	client := &fakeKMSClient{
		key:      &kmspb.CryptoKey{Name: "projects/p/locations/global/keyRings/r/cryptoKeys/validator"},
		getErr:   errors.New("readback unavailable"),
		getErrOn: 2,
	}
	g := newBindingTestGCP(t, client)
	require.ErrorContains(t, g.ClaimCluster(t.Context(), clusterA), "readback unavailable")
	require.Equal(t, 1, client.updates)
}

func TestGCPKeyVersionParsingRejectsAmbiguousResources(t *testing.T) {
	for _, value := range []string{
		"", "projects/p/locations/l/keyRings/r/cryptoKeys/k", "/" + testGCPKeyVersion,
		testGCPKeyVersion + "/", "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/",
	} {
		t.Run(value, func(t *testing.T) {
			_, err := gcpCryptoKeyName(value)
			require.Error(t, err)
		})
	}
}

func TestGCPVerifyCanSignStopsBlockedRequestOnCancellation(t *testing.T) {
	started := make(chan struct{})
	client := &fakeKMSClient{
		sign: func(ctx context.Context, _ *kmspb.AsymmetricSignRequest) (*kmspb.AsymmetricSignResponse, error) {
			close(started)
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
	g := newBindingTestGCP(t, client)
	g.pub = ed25519.GenPrivKey().PubKey()
	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() { result <- g.VerifyCanSign(ctx) }()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("KMS signing request did not start")
	}
	cancel()
	select {
	case err := <-result:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("KMS preflight did not stop after cancellation")
	}
}
