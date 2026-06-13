package backend

import (
	"fmt"
	"os"

	"github.com/cometbft/cometbft/crypto"
	cmtjson "github.com/cometbft/cometbft/libs/json"
	"github.com/cometbft/cometbft/privval"
)

// Software holds the consensus private key in process. It is the default
// backend for local testing; production deployments should use Vault.
type Software struct {
	priv crypto.PrivKey
}

// NewSoftware loads a priv_validator_key.json-compatible file.
func NewSoftware(keyFile string) (*Software, error) {
	if keyFile == "" {
		return nil, fmt.Errorf("software backend requires a key file")
	}
	data, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	var pvKey privval.FilePVKey
	if err := cmtjson.Unmarshal(data, &pvKey); err != nil {
		return nil, fmt.Errorf("parse key file %q: %w", keyFile, err)
	}
	if pvKey.PrivKey == nil {
		return nil, fmt.Errorf("key file %q has no priv_key", keyFile)
	}
	return &Software{priv: pvKey.PrivKey}, nil
}

// NewSoftwareFromPriv wraps an in-memory private key (used by tests).
func NewSoftwareFromPriv(priv crypto.PrivKey) *Software {
	return &Software{priv: priv}
}

func (s *Software) PubKey() (crypto.PubKey, error) { return s.priv.PubKey(), nil }

func (s *Software) Sign(signBytes []byte) ([]byte, error) { return s.priv.Sign(signBytes) }

func (s *Software) Close() error { return nil }
