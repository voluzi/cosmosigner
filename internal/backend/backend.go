// Package backend defines the KeyBackend interface — the signing oracle — and
// its v1 implementations. A KeyBackend produces signatures and exposes the
// durable Raft-history claim on its key resource; it performs NO per-sign
// ordering checks. The StateStore gate must always run first.
package backend

import (
	"context"
	"errors"
	"fmt"

	"github.com/cometbft/cometbft/crypto"

	"github.com/voluzi/cosmosigner/internal/clusterid"
)

// KeyBackend signs canonical sign-bytes with the validator consensus key.
type KeyBackend interface {
	// PubKey returns the ed25519 consensus public key.
	PubKey() (crypto.PubKey, error)
	// Sign returns the raw 64-byte ed25519 signature over signBytes.
	Sign(signBytes []byte) ([]byte, error)
	// ClusterBinding reads the immutable Raft-history claim attached to this key resource.
	ClusterBinding(ctx context.Context) (string, error)
	// ClaimCluster creates the claim if absent and never reassigns an existing owner.
	ClaimCluster(ctx context.Context, clusterID string) error
	// Close releases any resources (token renewers, clients).
	Close() error
}

var (
	ErrBindingUnclaimed   = errors.New("key resource is not claimed")
	ErrBindingCorrupt     = errors.New("key resource claim is corrupt")
	ErrBindingUnreadable  = errors.New("key resource claim is unreadable")
	ErrBindingMismatch    = errors.New("key resource is claimed by a different cluster")
	ErrBindingUnsupported = errors.New("key resource does not support persistent cluster binding")
)

// RequireClusterBinding fails unless the backend's durable claim exactly matches clusterID.
func RequireClusterBinding(ctx context.Context, b KeyBackend, clusterID string) error {
	if err := clusterid.Validate(clusterID); err != nil {
		return fmt.Errorf("invalid expected cluster ID: %w", err)
	}
	actual, err := b.ClusterBinding(ctx)
	if err != nil {
		if errors.Is(err, ErrBindingUnclaimed) {
			return fmt.Errorf("cluster %s cannot use unclaimed key resource: %w", clusterID, err)
		}
		return err
	}
	if actual != clusterID {
		return fmt.Errorf("%w: resource %s expected cluster %s, actual cluster %s", ErrBindingMismatch, BindingResource(b), clusterID, actual)
	}
	return nil
}

// BindingResource describes the provider resource that carries the cluster claim.
func BindingResource(b KeyBackend) string {
	if describer, ok := b.(interface{ bindingResource() string }); ok {
		return describer.bindingResource()
	}
	return "key resource"
}

// Type identifies a KeyBackend implementation.
type Type string

const (
	TypeSoftware Type = "software"
	TypeVault    Type = "vault"
	TypeGCPKMS   Type = "gcpkms"
)

// Config selects and configures a KeyBackend.
type Config struct {
	Type            Type         `yaml:"type"     env:"COSMOSIGNER_BACKEND"  default:"software"`
	SoftwareKeyFile string       `yaml:"key_file" env:"COSMOSIGNER_KEY_FILE"`
	Vault           VaultConfig  `yaml:"vault"`
	GCPKMS          GCPKMSConfig `yaml:"gcp"`
}

// New builds the KeyBackend described by cfg.
func New(cfg Config) (KeyBackend, error) {
	switch cfg.Type {
	case TypeSoftware, "":
		return NewSoftware(cfg.SoftwareKeyFile)
	case TypeVault:
		return NewVault(cfg.Vault)
	case TypeGCPKMS:
		return NewGCPKMS(cfg.GCPKMS)
	default:
		return nil, fmt.Errorf("unknown backend type %q", cfg.Type)
	}
}
