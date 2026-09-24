package cmd

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/cometbft/cometbft/crypto/ed25519"
	cmtlog "github.com/cometbft/cometbft/libs/log"
	"github.com/stretchr/testify/require"

	"github.com/voluzi/cosmosigner/internal/backend"
	"github.com/voluzi/cosmosigner/internal/config"
)

const otherClusterID = "9f1c2a64-0d8b-4f55-9a9d-6b2f0e5c7a31"

// claimingBackend starts unclaimed (or claimed by owner) and records claims like a real backend:
// the first claim wins and a different owner is never replaced.
type claimingBackend struct {
	startupTestBackend
	owner    string
	claims   []string
	claimErr error
}

func (b *claimingBackend) ClusterBinding(context.Context) (string, error) {
	b.bindingReads++
	if b.owner == "" {
		return "", backend.ErrBindingUnclaimed
	}
	return b.owner, nil
}

func (b *claimingBackend) ClaimCluster(_ context.Context, id string) error {
	b.claims = append(b.claims, id)
	if b.claimErr != nil {
		return b.claimErr
	}
	if b.owner == "" {
		b.owner = id
	}
	if b.owner != id {
		return backend.ErrBindingMismatch
	}
	return nil
}

func testClaimer(be backend.KeyBackend) startupClaimer {
	return claimWithConfig(backend.Config{Type: backend.TypeSoftware}, be, false, cmtlog.NewNopLogger())
}

func TestPrepareStartupClaimsAnUnclaimedKeyWhenEnabled(t *testing.T) {
	be := &claimingBackend{startupTestBackend: startupTestBackend{pub: ed25519.GenPrivKey().PubKey()}}
	store := &startupTestStore{clusterID: startTestClusterID}

	id, err := prepareStartupWithClaim(t.Context(), be, store, false, testClaimer(be))
	require.NoError(t, err)
	require.Equal(t, startTestClusterID, id)
	require.Equal(t, []string{startTestClusterID}, be.claims)
	// The claim is re-read through the runtime backend before signing is enabled.
	require.Equal(t, 2, be.bindingReads)
	require.Equal(t, 1, be.preflights)
	require.Equal(t, 1, be.renewals)
}

func TestPrepareStartupNeverClaimsAKeyOwnedByAnotherCluster(t *testing.T) {
	be := &claimingBackend{startupTestBackend: startupTestBackend{pub: ed25519.GenPrivKey().PubKey()}, owner: otherClusterID}
	store := &startupTestStore{clusterID: startTestClusterID}

	_, err := prepareStartupWithClaim(t.Context(), be, store, false, testClaimer(be))
	require.ErrorIs(t, err, backend.ErrBindingMismatch)
	require.Empty(t, be.claims)
	require.Zero(t, be.preflights)
	require.Zero(t, be.renewals)
}

func TestPrepareStartupSurfacesAFailedClaim(t *testing.T) {
	claimErr := errors.New("permission denied")
	be := &claimingBackend{startupTestBackend: startupTestBackend{pub: ed25519.GenPrivKey().PubKey()}, claimErr: claimErr}
	store := &startupTestStore{clusterID: startTestClusterID}

	_, err := prepareStartupWithClaim(t.Context(), be, store, false, testClaimer(be))
	require.ErrorIs(t, err, claimErr)
	require.Zero(t, be.preflights)
	require.Zero(t, be.renewals)
}

func TestPrepareStartupWithoutClaimLeavesAnUnclaimedKeyUnclaimed(t *testing.T) {
	be := &claimingBackend{startupTestBackend: startupTestBackend{pub: ed25519.GenPrivKey().PubKey()}}
	store := &startupTestStore{clusterID: startTestClusterID}

	_, err := prepareStartupWithClaim(t.Context(), be, store, false, nil)
	require.ErrorIs(t, err, backend.ErrBindingUnclaimed)
	require.Empty(t, be.claims)
}

func TestPrepareStartupInitializeOnlyNeverClaims(t *testing.T) {
	be := &claimingBackend{startupTestBackend: startupTestBackend{pub: ed25519.GenPrivKey().PubKey()}}
	store := &startupTestStore{clusterID: startTestClusterID}

	_, err := prepareStartupWithClaim(t.Context(), be, store, true, testClaimer(be))
	require.NoError(t, err)
	require.Empty(t, be.claims)
	require.Zero(t, be.bindingReads)
}

// With separate claim credentials the claim goes through a second backend built from them; the
// runtime backend, which here may not claim, is never asked to.
func TestClaimWithConfigUsesSeparateCredentialsBackend(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "priv_validator_key.json")
	_, err := backend.ProvisionSoftwareKey(t.Context(), keyFile, false)
	require.NoError(t, err)
	runtime := &claimingBackend{
		startupTestBackend: startupTestBackend{pub: ed25519.GenPrivKey().PubKey()},
		claimErr:           errors.New("runtime identity may not claim"),
	}
	claimCfg := backend.Config{Type: backend.TypeSoftware, SoftwareKeyFile: keyFile}

	require.NoError(t, claimWithConfig(claimCfg, runtime, true, cmtlog.NewNopLogger())(t.Context(), startTestClusterID))
	require.Empty(t, runtime.claims)
	claimed, err := backend.NewSoftware(keyFile)
	require.NoError(t, err)
	owner, err := claimed.ClusterBinding(t.Context())
	require.NoError(t, err)
	require.Equal(t, startTestClusterID, owner)

	// Without separate credentials the runtime backend claims, and its refusal is surfaced.
	err = claimWithConfig(claimCfg, runtime, false, cmtlog.NewNopLogger())(t.Context(), startTestClusterID)
	require.ErrorContains(t, err, "runtime identity may not claim")
	require.Equal(t, []string{startTestClusterID}, runtime.claims)
}

func TestOverlayStartFlagsSetsClaimSettings(t *testing.T) {
	cmd := NewStartCmd()
	require.NoError(t, cmd.Flags().Set("claim-if-unclaimed", "true"))
	require.NoError(t, cmd.Flags().Set("vault-claim-token-file", "/vault/claim"))
	require.NoError(t, cmd.Flags().Set("gcp-claim-credentials-file", "/gcp/claim.json"))
	require.NoError(t, cmd.Flags().Set("binding-file", "/data/cluster.json"))
	cfg := &config.Config{}
	require.NoError(t, overlayStartFlags(cmd, cfg))
	require.True(t, cfg.ClaimIfUnclaimed)
	require.Equal(t, "/vault/claim", cfg.Backend.Vault.ClaimTokenFile)
	require.Equal(t, "/gcp/claim.json", cfg.Backend.GCPKMS.ClaimCredentialsFile)
	require.Equal(t, "/data/cluster.json", cfg.Backend.SoftwareBindingFile)
}
