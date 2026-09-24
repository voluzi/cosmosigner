package backend

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/googleapis/gax-go/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const (
	testImportRing = "projects/p/locations/global/keyRings/r"
	testImportKey  = testImportRing + "/cryptoKeys/validator"
	testImportJob  = testImportRing + "/importJobs/validator-import"
)

// fakeImportClient models Cloud KMS resources: a nil field means the resource
// does not exist; an entry in errs makes that method fail.
type fakeImportClient struct {
	ring *kmspb.KeyRing
	key  *kmspb.CryptoKey
	job  *kmspb.ImportJob

	errs    map[string]error
	wrapPEM string

	// racedKey, when set, appears just as CreateCryptoKey runs (another writer won).
	racedKey *kmspb.CryptoKey

	calls []string
}

func (f *fakeImportClient) call(name string) error {
	f.calls = append(f.calls, name)
	return f.errs[name]
}

var errUnexpected = errors.New("unexpected call")

func (f *fakeImportClient) GetKeyRing(context.Context, *kmspb.GetKeyRingRequest, ...gax.CallOption) (*kmspb.KeyRing, error) {
	if err := f.call("GetKeyRing"); err != nil {
		return nil, err
	}
	if f.ring == nil {
		return nil, status.Error(codes.NotFound, "no ring")
	}
	return proto.Clone(f.ring).(*kmspb.KeyRing), nil
}

func (f *fakeImportClient) CreateKeyRing(_ context.Context, req *kmspb.CreateKeyRingRequest, _ ...gax.CallOption) (*kmspb.KeyRing, error) {
	if err := f.call("CreateKeyRing"); err != nil {
		return nil, err
	}
	if f.ring != nil {
		return nil, status.Error(codes.AlreadyExists, "ring exists")
	}
	f.ring = &kmspb.KeyRing{Name: req.Parent + "/keyRings/" + req.KeyRingId}
	return f.ring, nil
}

func (f *fakeImportClient) GetCryptoKey(context.Context, *kmspb.GetCryptoKeyRequest, ...gax.CallOption) (*kmspb.CryptoKey, error) {
	if err := f.call("GetCryptoKey"); err != nil {
		return nil, err
	}
	if f.key == nil {
		return nil, status.Error(codes.NotFound, "no key")
	}
	return proto.Clone(f.key).(*kmspb.CryptoKey), nil
}

func (f *fakeImportClient) CreateCryptoKey(_ context.Context, req *kmspb.CreateCryptoKeyRequest, _ ...gax.CallOption) (*kmspb.CryptoKey, error) {
	if err := f.call("CreateCryptoKey"); err != nil {
		return nil, err
	}
	if f.racedKey != nil {
		f.key = f.racedKey
	}
	if f.ring == nil {
		return nil, status.Error(codes.NotFound, "no ring")
	}
	if f.key != nil {
		return nil, status.Error(codes.AlreadyExists, "key exists")
	}
	f.key = proto.Clone(req.CryptoKey).(*kmspb.CryptoKey)
	f.key.Name = req.Parent + "/cryptoKeys/" + req.CryptoKeyId
	return f.key, nil
}

func (f *fakeImportClient) GetImportJob(context.Context, *kmspb.GetImportJobRequest, ...gax.CallOption) (*kmspb.ImportJob, error) {
	if err := f.call("GetImportJob"); err != nil {
		return nil, err
	}
	if f.job == nil {
		return nil, status.Error(codes.NotFound, "no job")
	}
	return proto.Clone(f.job).(*kmspb.ImportJob), nil
}

func (f *fakeImportClient) CreateImportJob(_ context.Context, req *kmspb.CreateImportJobRequest, _ ...gax.CallOption) (*kmspb.ImportJob, error) {
	if err := f.call("CreateImportJob"); err != nil {
		return nil, err
	}
	if f.job != nil {
		return nil, status.Error(codes.AlreadyExists, "job exists")
	}
	f.job = proto.Clone(req.ImportJob).(*kmspb.ImportJob)
	f.job.Name = req.Parent + "/importJobs/" + req.ImportJobId
	f.job.State = kmspb.ImportJob_ACTIVE
	f.job.PublicKey = &kmspb.ImportJob_WrappingPublicKey{Pem: f.wrapPEM}
	return f.job, nil
}

func (f *fakeImportClient) ImportCryptoKeyVersion(_ context.Context, req *kmspb.ImportCryptoKeyVersionRequest, _ ...gax.CallOption) (*kmspb.CryptoKeyVersion, error) {
	if err := f.call("ImportCryptoKeyVersion"); err != nil {
		return nil, err
	}
	if f.key == nil || req.Parent != f.key.Name {
		return nil, errUnexpected
	}
	return &kmspb.CryptoKeyVersion{Name: req.Parent + "/cryptoKeyVersions/3", State: kmspb.CryptoKeyVersion_PENDING_IMPORT}, nil
}

func (f *fakeImportClient) GetCryptoKeyVersion(_ context.Context, req *kmspb.GetCryptoKeyVersionRequest, _ ...gax.CallOption) (*kmspb.CryptoKeyVersion, error) {
	if err := f.call("GetCryptoKeyVersion"); err != nil {
		return nil, err
	}
	return &kmspb.CryptoKeyVersion{Name: req.Name, State: kmspb.CryptoKeyVersion_ENABLED}, nil
}

func (f *fakeImportClient) called(name string) bool {
	for _, c := range f.calls {
		if c == name {
			return true
		}
	}
	return false
}

func testWrappingPEM(t *testing.T) string {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func testImportConfig() GCPImportConfig {
	return GCPImportConfig{
		Project:     "p",
		Location:    "global",
		KeyRing:     "r",
		Key:         "validator",
		ImportJobID: "validator-import",
		Protection:  kmspb.ProtectionLevel_SOFTWARE,
	}
}

func importableKey() *kmspb.CryptoKey {
	return &kmspb.CryptoKey{
		Name:    testImportKey,
		Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
		VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
			Algorithm:       kmspb.CryptoKeyVersion_EC_SIGN_ED25519,
			ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE,
		},
		ImportOnly: true,
	}
}

func activeJob(pemKey string) *kmspb.ImportJob {
	return &kmspb.ImportJob{
		Name:            testImportJob,
		ImportMethod:    kmspb.ImportJob_RSA_OAEP_3072_SHA256,
		ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE,
		State:           kmspb.ImportJob_ACTIVE,
		PublicKey:       &kmspb.ImportJob_WrappingPublicKey{Pem: pemKey},
	}
}

var testPKCS8 = make([]byte, 48)

// An identity scoped to an existing key and job must be able to import: no
// create call (and no key ring read) may be issued for resources that exist.
func TestGCPImportExistingKeyAndJobCreatesNothing(t *testing.T) {
	pemKey := testWrappingPEM(t)
	client := &fakeImportClient{
		ring: &kmspb.KeyRing{Name: testImportRing},
		key:  importableKey(),
		job:  activeJob(pemKey),
	}

	version, ready, err := gcpImportKey(t.Context(), client, testImportConfig(), testPKCS8)
	require.NoError(t, err)
	require.True(t, ready)
	require.Equal(t, testImportKey+"/cryptoKeyVersions/3", version)
	for _, c := range []string{"GetKeyRing", "CreateKeyRing", "CreateCryptoKey", "CreateImportJob"} {
		require.False(t, client.called(c), "%s must not be called; calls: %v", c, client.calls)
	}
}

func TestGCPImportCreatesMissingRingKeyAndJob(t *testing.T) {
	client := &fakeImportClient{wrapPEM: testWrappingPEM(t)}

	version, ready, err := gcpImportKey(t.Context(), client, testImportConfig(), testPKCS8)
	require.NoError(t, err)
	require.True(t, ready)
	require.Equal(t, testImportKey+"/cryptoKeyVersions/3", version)
	require.Equal(t, []string{
		"GetCryptoKey", "GetKeyRing", "CreateKeyRing", "CreateCryptoKey",
		"GetImportJob", "CreateImportJob", "GetImportJob",
		"ImportCryptoKeyVersion", "GetCryptoKeyVersion",
	}, client.calls)
	require.Equal(t, kmspb.CryptoKey_ASYMMETRIC_SIGN, client.key.Purpose)
	require.Equal(t, kmspb.CryptoKeyVersion_EC_SIGN_ED25519, client.key.VersionTemplate.Algorithm)
	require.Equal(t, kmspb.ProtectionLevel_SOFTWARE, client.key.VersionTemplate.ProtectionLevel)
}

func TestGCPImportExistingRingCreatesOnlyKey(t *testing.T) {
	client := &fakeImportClient{ring: &kmspb.KeyRing{Name: testImportRing}, job: activeJob(testWrappingPEM(t))}

	_, _, err := gcpImportKey(t.Context(), client, testImportConfig(), testPKCS8)
	require.NoError(t, err)
	require.False(t, client.called("CreateKeyRing"), "calls: %v", client.calls)
	require.True(t, client.called("CreateCryptoKey"))
}

func TestGCPImportRejectsUnusableExistingKey(t *testing.T) {
	cases := map[string]func(*kmspb.CryptoKey){
		"purpose":    func(k *kmspb.CryptoKey) { k.Purpose = kmspb.CryptoKey_ENCRYPT_DECRYPT },
		"algorithm":  func(k *kmspb.CryptoKey) { k.VersionTemplate.Algorithm = kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256 },
		"protection": func(k *kmspb.CryptoKey) { k.VersionTemplate.ProtectionLevel = kmspb.ProtectionLevel_HSM },
		"template":   func(k *kmspb.CryptoKey) { k.VersionTemplate = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			key := importableKey()
			mutate(key)
			client := &fakeImportClient{ring: &kmspb.KeyRing{Name: testImportRing}, key: key, job: activeJob(testWrappingPEM(t))}

			_, _, err := gcpImportKey(t.Context(), client, testImportConfig(), testPKCS8)
			require.ErrorContains(t, err, "cosmosigner requires")
			require.Equal(t, []string{"GetCryptoKey"}, client.calls)
		})
	}
}

func TestGCPImportRejectsUnusableExistingJob(t *testing.T) {
	cases := map[string]func(*kmspb.ImportJob){
		"method":     func(j *kmspb.ImportJob) { j.ImportMethod = kmspb.ImportJob_RSA_OAEP_4096_SHA1_AES_256 },
		"protection": func(j *kmspb.ImportJob) { j.ProtectionLevel = kmspb.ProtectionLevel_HSM },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			job := activeJob(testWrappingPEM(t))
			mutate(job)
			client := &fakeImportClient{ring: &kmspb.KeyRing{Name: testImportRing}, key: importableKey(), job: job}

			_, _, err := gcpImportKey(t.Context(), client, testImportConfig(), testPKCS8)
			require.ErrorContains(t, err, "need RSA_OAEP_3072_SHA256 or RSA_OAEP_4096_SHA256")
			require.False(t, client.called("ImportCryptoKeyVersion"), "calls: %v", client.calls)
		})
	}
}

// A read the identity may not perform must fail the import, never fall
// through to the create that the same identity presumably cannot do either.
// RSA_OAEP_4096_SHA256 is the same direct OAEP-SHA256 wrapping with a larger key.
func TestGCPImportAcceptsExisting4096OAEPJob(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	job := activeJob(string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})))
	job.ImportMethod = kmspb.ImportJob_RSA_OAEP_4096_SHA256
	client := &fakeImportClient{ring: &kmspb.KeyRing{Name: testImportRing}, key: importableKey(), job: job}

	_, _, err = gcpImportKey(t.Context(), client, testImportConfig(), testPKCS8)
	require.NoError(t, err)
	require.True(t, client.called("ImportCryptoKeyVersion"))
}

func TestGCPImportDoesNotCreateOnDeniedRead(t *testing.T) {
	denied := status.Error(codes.PermissionDenied, "denied")
	cases := map[string]struct {
		client *fakeImportClient
		calls  []string
	}{
		"crypto key": {
			client: &fakeImportClient{errs: map[string]error{"GetCryptoKey": denied}},
			calls:  []string{"GetCryptoKey"},
		},
		"key ring": {
			client: &fakeImportClient{errs: map[string]error{"GetKeyRing": denied}},
			calls:  []string{"GetCryptoKey", "GetKeyRing"},
		},
		"import job": {
			client: &fakeImportClient{ring: &kmspb.KeyRing{Name: testImportRing}, key: importableKey(), errs: map[string]error{"GetImportJob": denied}},
			calls:  []string{"GetCryptoKey", "GetImportJob"},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, _, err := gcpImportKey(t.Context(), tc.client, testImportConfig(), testPKCS8)
			require.Equal(t, codes.PermissionDenied, status.Code(err))
			require.Equal(t, tc.calls, tc.client.calls)
		})
	}
}

// Losing the CreateCryptoKey race to a writer that made an unusable key must
// not import into it.
func TestGCPImportValidatesKeyCreatedByRacingWriter(t *testing.T) {
	raced := importableKey()
	raced.VersionTemplate.ProtectionLevel = kmspb.ProtectionLevel_HSM
	client := &fakeImportClient{ring: &kmspb.KeyRing{Name: testImportRing}, racedKey: raced, job: activeJob(testWrappingPEM(t))}

	_, _, err := gcpImportKey(t.Context(), client, testImportConfig(), testPKCS8)
	require.ErrorContains(t, err, "cosmosigner requires")
	require.Equal(t, []string{"GetCryptoKey", "GetKeyRing", "CreateCryptoKey", "GetCryptoKey"}, client.calls)
}
