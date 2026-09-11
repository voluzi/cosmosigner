package backend

import (
	"encoding/base64"
	"sync"
	"testing"

	"github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/stretchr/testify/require"
)

const (
	determinismSequentialAttempts = 4
	determinismConcurrentAttempts = 8
)

const determinismTestMessage = "cosmosigner/backend determinism conformance - not a consensus message"

func requireSignDeterminism(t *testing.T, backends ...KeyBackend) {
	t.Helper()
	require.GreaterOrEqual(t, len(backends), 2, "conformance requires separate backend instances")
	message := []byte(determinismTestMessage)

	pub, err := backends[0].PubKey()
	require.NoError(t, err)
	for _, be := range backends[1:] {
		otherPub, err := be.PubKey()
		require.NoError(t, err)
		require.Equal(t, pub.Bytes(), otherPub.Bytes(), "backend instances must use the same key")
	}

	firstSignature, err := backends[0].Sign(message)
	require.NoError(t, err)
	require.Len(t, firstSignature, ed25519.SignatureSize)
	require.True(t, pub.VerifySignature(message, firstSignature))

	// Keep an independent baseline so a backend that reuses its result buffer
	// cannot make different signatures appear equal.
	baseline := append([]byte(nil), firstSignature...)

	for i := 0; i < determinismSequentialAttempts; i++ {
		signature, err := backends[i%len(backends)].Sign(message)
		require.NoError(t, err, "sequential attempt %d", i)
		require.Len(t, signature, ed25519.SignatureSize)
		require.True(t, pub.VerifySignature(message, signature))
		require.Equal(t, baseline, signature)
	}

	type signResult struct {
		signature []byte
		err       error
	}
	results := make([]signResult, determinismConcurrentAttempts)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results[i].signature, results[i].err = backends[i%len(backends)].Sign(message)
		}()
	}
	close(start)
	wg.Wait()

	for i, result := range results {
		require.NoError(t, result.err, "concurrent attempt %d", i)
		require.Len(t, result.signature, ed25519.SignatureSize)
		require.True(t, pub.VerifySignature(message, result.signature))
		require.Equal(t, baseline, result.signature)
	}
}

func TestSoftwareSignDeterminism(t *testing.T) {
	priv := ed25519.GenPrivKey()
	requireSignDeterminism(t, NewSoftwareFromPriv(priv), NewSoftwareFromPriv(priv))
}

func TestParseTransitSignature(t *testing.T) {
	raw := make([]byte, ed25519.SignatureSize)
	for i := range raw {
		raw[i] = byte(i)
	}
	good := "vault:v1:" + base64.StdEncoding.EncodeToString(raw)
	got, err := parseTransitSignature(good)
	require.NoError(t, err)
	require.Equal(t, raw, got)

	for _, bad := range []string{
		"not-a-signature",
		"vault:v1:" + base64.StdEncoding.EncodeToString([]byte("too-short")),
		"other:v1:" + base64.StdEncoding.EncodeToString(raw),
	} {
		_, err := parseTransitSignature(bad)
		require.Error(t, err, "input %q should fail", bad)
	}
}
