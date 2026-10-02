package backend

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/cometbft/cometbft/crypto"
)

// Software holds the consensus private key in process. It is the default
// backend for local testing; production deployments should use Vault.
type Software struct {
	priv        crypto.PrivKey
	keyPath     string
	bindingPath string
	// lockPath is the base path of the claim lock: the key path by default, or the binding path
	// when the marker is relocated (the key directory may be read-only).
	lockPath       string
	bindingOps     softwareBindingOps
	operationHooks softwareOperationHooks
}

type softwareBindingOps struct {
	createTemp func(string, string) (*os.File, error)
	open       func(string) (*os.File, error)
	link       func(string, string) error
	remove     func(string) error
	sync       func(*os.File) error
}

func defaultSoftwareBindingOps() softwareBindingOps {
	return softwareBindingOps{
		createTemp: os.CreateTemp,
		open:       os.Open,
		link:       os.Link,
		remove:     os.Remove,
		sync:       func(file *os.File) error { return file.Sync() },
	}
}

type softwareBindingRecord struct {
	Version   int    `json:"version"`
	ClusterID string `json:"cluster_id"`
	PublicKey string `json:"public_key"`
}

// NewSoftware loads a priv_validator_key.json-compatible file.
func NewSoftware(keyFile string) (*Software, error) {
	return NewSoftwareWithBindingFile(keyFile, "")
}

// NewSoftwareWithBindingFile loads a key file and keeps its cluster marker at bindingFile, or next
// to the key when bindingFile is empty.
func NewSoftwareWithBindingFile(keyFile, bindingFile string) (*Software, error) {
	canonicalPath, err := resolveExistingSoftwareKeyPath(keyFile)
	if err != nil {
		return nil, err
	}
	priv, err := loadSoftwarePrivateKey(canonicalPath)
	if err != nil {
		return nil, err
	}
	bindingPath, lockPath := canonicalPath+softwareBindingSuffix, canonicalPath
	if bindingFile != "" {
		if bindingPath, err = resolveBindingPath(bindingFile, "software"); err != nil {
			return nil, err
		}
		if bindingPath == canonicalPath {
			return nil, fmt.Errorf("software binding file %q must differ from the key file", bindingFile)
		}
		lockPath = bindingPath
	}
	return &Software{
		priv:        priv,
		keyPath:     canonicalPath,
		bindingPath: bindingPath,
		lockPath:    lockPath,
		bindingOps:  defaultSoftwareBindingOps(),
	}, nil
}

// NewSoftwareFromPriv wraps an in-memory private key (used by tests).
func NewSoftwareFromPriv(priv crypto.PrivKey) *Software {
	return &Software{priv: priv}
}

func (s *Software) PubKey() (crypto.PubKey, error) { return s.priv.PubKey(), nil }

func (s *Software) Sign(signBytes []byte) ([]byte, error) { return s.priv.Sign(signBytes) }

func (s *Software) fileBinding() *fileBinding {
	return &fileBinding{kind: "software", bindingPath: s.bindingPath, lockPath: s.lockPath,
		bindingOps: s.bindingOps, operationHooks: s.operationHooks, publicKey: s.priv.PubKey()}
}

func (s *Software) ClusterBinding(ctx context.Context) (string, error) {
	if s.bindingPath == "" {
		return "", ErrBindingUnsupported
	}
	return s.fileBinding().read(ctx)
}

func (s *Software) ClaimCluster(ctx context.Context, id string) error {
	if s.bindingPath == "" {
		return ErrBindingUnsupported
	}
	return s.fileBinding().claim(ctx, id, func() error {
		diskPriv, err := loadSoftwarePrivateKey(s.keyPath)
		if err != nil {
			return fmt.Errorf("%w: validate software key %q before claim: %v", ErrBindingCorrupt, s.keyPath, err)
		}
		if !diskPriv.Equals(s.priv) {
			return fmt.Errorf("%w: software key %q changed after it was loaded", ErrBindingCorrupt, s.keyPath)
		}

		return nil
	})
}

func (s *Software) bindingResource() string {
	if s.bindingPath == "" {
		return "in-memory software key"
	}
	return s.bindingPath
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func requireClaimOwner(resource, expected, actual string) error {
	if actual == expected {
		return nil
	}
	return fmt.Errorf("%w: resource %q expected cluster %s, actual cluster %s", ErrBindingMismatch, resource, expected, actual)
}

func (s *Software) Close() error { return nil }
