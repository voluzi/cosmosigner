// Package backend defines the KeyBackend interface — the signing oracle — and
// its v1 implementations. A KeyBackend only produces signatures and exposes the
// public key; it performs NO double-sign / ordering checks. The StateStore gate
// must always run first.
package backend

import (
	"fmt"

	"github.com/cometbft/cometbft/crypto"
)

// KeyBackend signs canonical sign-bytes with the validator consensus key.
type KeyBackend interface {
	// PubKey returns the ed25519 consensus public key.
	PubKey() (crypto.PubKey, error)
	// Sign returns the raw 64-byte ed25519 signature over signBytes.
	Sign(signBytes []byte) ([]byte, error)
	// Close releases any resources (token renewers, clients).
	Close() error
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
