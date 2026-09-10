package backend

import (
	"context"
	"fmt"
	"strings"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	"github.com/voluzi/cosmosigner/internal/clusterid"
)

const gcpClusterIDLabel = "cosmosigner-cluster-id"

func (g *GCPKMS) bindingResource() string {
	return fmt.Sprintf("GCP CryptoKey %s label %s", g.keyResource, gcpClusterIDLabel)
}

func gcpCryptoKeyName(version string) (string, error) {
	parts := strings.Split(version, "/")
	if len(parts) != 10 || parts[0] != "projects" || parts[2] != "locations" ||
		parts[4] != "keyRings" || parts[6] != "cryptoKeys" || parts[8] != "cryptoKeyVersions" {
		return "", fmt.Errorf("invalid GCP CryptoKeyVersion resource %q", version)
	}
	for i := 1; i < len(parts); i += 2 {
		if parts[i] == "" || parts[i] == "." || parts[i] == ".." || strings.TrimSpace(parts[i]) != parts[i] {
			return "", fmt.Errorf("invalid GCP CryptoKeyVersion resource %q", version)
		}
	}
	return strings.Join(parts[:8], "/"), nil
}

func (g *GCPKMS) getCryptoKey(ctx context.Context) (*kmspb.CryptoKey, error) {
	cctx, cancel := context.WithTimeout(ctx, g.timeout)
	defer cancel()
	key, err := g.client.GetCryptoKey(cctx, &kmspb.GetCryptoKeyRequest{Name: g.keyResource})
	if err != nil {
		return nil, fmt.Errorf("get GCP CryptoKey %q: %w", g.keyResource, err)
	}
	if key == nil || key.Name != g.keyResource {
		return nil, fmt.Errorf("GCP CryptoKey response resource mismatch for %q", g.keyResource)
	}
	return key, nil
}

func (g *GCPKMS) ClusterBinding(ctx context.Context) (string, error) {
	key, err := g.getCryptoKey(ctx)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrBindingUnreadable, err)
	}
	id, exists := key.Labels[gcpClusterIDLabel]
	if !exists {
		return "", fmt.Errorf("%w: GCP CryptoKey %q has no %s label", ErrBindingUnclaimed, g.keyResource, gcpClusterIDLabel)
	}
	if err := clusterid.Validate(id); err != nil {
		return "", fmt.Errorf("%w: GCP CryptoKey %q has invalid %s label: %v", ErrBindingCorrupt, g.keyResource, gcpClusterIDLabel, err)
	}
	return id, nil
}

func (g *GCPKMS) ClaimCluster(ctx context.Context, id string) error {
	if err := clusterid.Validate(id); err != nil {
		return fmt.Errorf("invalid cluster ID: %w", err)
	}
	key, err := g.getCryptoKey(ctx)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBindingUnreadable, err)
	}
	if actual, exists := key.Labels[gcpClusterIDLabel]; exists {
		if err := clusterid.Validate(actual); err != nil {
			return fmt.Errorf("%w: GCP CryptoKey %q has invalid %s label: %v", ErrBindingCorrupt, g.keyResource, gcpClusterIDLabel, err)
		}
		return requireClaimOwner(g.keyResource, id, actual)
	}

	labels := make(map[string]string, len(key.Labels)+1)
	for name, value := range key.Labels {
		labels[name] = value
	}
	labels[gcpClusterIDLabel] = id
	cctx, cancel := context.WithTimeout(ctx, g.timeout)
	defer cancel()
	if _, err := g.client.UpdateCryptoKey(cctx, &kmspb.UpdateCryptoKeyRequest{
		CryptoKey:  &kmspb.CryptoKey{Name: g.keyResource, Labels: labels},
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"labels"}},
	}); err != nil {
		return fmt.Errorf("update GCP CryptoKey %q cluster label: %w", g.keyResource, err)
	}
	actual, err := g.ClusterBinding(ctx)
	if err != nil {
		return fmt.Errorf("reread GCP CryptoKey %q after claim: %w", g.keyResource, err)
	}
	return requireClaimOwner(g.keyResource, id, actual)
}
