package backend

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/cometbft/cometbft/crypto"

	"github.com/voluzi/cosmosigner/internal/clusterid"
)

// Software holds the consensus private key in process. It is the default
// backend for local testing; production deployments should use Vault.
type Software struct {
	priv           crypto.PrivKey
	keyPath        string
	bindingPath    string
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
	canonicalPath, err := resolveExistingSoftwareKeyPath(keyFile)
	if err != nil {
		return nil, err
	}
	priv, err := loadSoftwarePrivateKey(canonicalPath)
	if err != nil {
		return nil, err
	}
	return &Software{
		priv:        priv,
		keyPath:     canonicalPath,
		bindingPath: canonicalPath + softwareBindingSuffix,
		bindingOps:  defaultSoftwareBindingOps(),
	}, nil
}

// NewSoftwareFromPriv wraps an in-memory private key (used by tests).
func NewSoftwareFromPriv(priv crypto.PrivKey) *Software {
	return &Software{priv: priv}
}

func (s *Software) PubKey() (crypto.PubKey, error) { return s.priv.PubKey(), nil }

func (s *Software) Sign(signBytes []byte) ([]byte, error) { return s.priv.Sign(signBytes) }

func (s *Software) ClusterBinding(ctx context.Context) (string, error) {
	if s.bindingPath == "" {
		return "", ErrBindingUnsupported
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	data, err := os.ReadFile(s.bindingPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("%w: software marker %q", ErrBindingUnclaimed, s.bindingPath)
		}
		return "", fmt.Errorf("%w: read software marker %q: %v", ErrBindingUnreadable, s.bindingPath, err)
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}

	var record softwareBindingRecord
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return "", fmt.Errorf("%w: decode software marker %q: %v", ErrBindingCorrupt, s.bindingPath, err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return "", fmt.Errorf("%w: decode software marker %q: %v", ErrBindingCorrupt, s.bindingPath, err)
	}
	if record.Version != 1 {
		return "", fmt.Errorf("%w: software marker %q has version %d", ErrBindingCorrupt, s.bindingPath, record.Version)
	}
	if err := clusterid.Validate(record.ClusterID); err != nil {
		return "", fmt.Errorf("%w: software marker %q has invalid cluster ID: %v", ErrBindingCorrupt, s.bindingPath, err)
	}
	pub, err := s.PubKey()
	if err != nil {
		return "", fmt.Errorf("read software key public key: %w", err)
	}
	wantPublicKey := base64.StdEncoding.EncodeToString(pub.Bytes())
	if record.PublicKey != wantPublicKey {
		return "", fmt.Errorf("%w: software marker %q belongs to different key material", ErrBindingCorrupt, s.bindingPath)
	}
	return record.ClusterID, nil
}

func (s *Software) ClaimCluster(ctx context.Context, id string) error {
	if s.bindingPath == "" {
		return ErrBindingUnsupported
	}
	if err := clusterid.Validate(id); err != nil {
		return fmt.Errorf("invalid cluster ID: %w", err)
	}
	return withSoftwareKeyLock(ctx, s.keyPath, s.operationHooks, func() error {
		diskPriv, err := loadSoftwarePrivateKey(s.keyPath)
		if err != nil {
			return fmt.Errorf("%w: validate software key %q before claim: %v", ErrBindingCorrupt, s.keyPath, err)
		}
		if !diskPriv.Equals(s.priv) {
			return fmt.Errorf("%w: software key %q changed after it was loaded", ErrBindingCorrupt, s.keyPath)
		}

		owner, err := s.ClusterBinding(ctx)
		switch {
		case err == nil:
			return errors.Join(s.syncPublishedBinding(), requireClaimOwner(s.bindingPath, id, owner))
		case !errors.Is(err, ErrBindingUnclaimed):
			return err
		}

		pub, err := s.PubKey()
		if err != nil {
			return fmt.Errorf("read software key public key: %w", err)
		}
		data, err := json.Marshal(softwareBindingRecord{
			Version: 1, ClusterID: id, PublicKey: base64.StdEncoding.EncodeToString(pub.Bytes()),
		})
		if err != nil {
			return fmt.Errorf("encode software marker: %w", err)
		}
		data = append(data, '\n')

		directory := filepath.Dir(s.bindingPath)
		file, err := s.bindingOps.createTemp(directory, "."+filepath.Base(s.bindingPath)+".tmp-*")
		if err != nil {
			return fmt.Errorf("create temporary software marker in %q: %w", directory, err)
		}
		tempPath := file.Name()
		fileClosed := false
		defer func() {
			if !fileClosed {
				_ = file.Close()
			}
			_ = s.bindingOps.remove(tempPath)
		}()
		if _, err := io.Copy(file, bytes.NewReader(data)); err != nil {
			return fmt.Errorf("write temporary software marker %q: %w", tempPath, err)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := s.bindingOps.sync(file); err != nil {
			return fmt.Errorf("sync temporary software marker %q: %w", tempPath, err)
		}
		if err := file.Close(); err != nil {
			return fmt.Errorf("close temporary software marker %q: %w", tempPath, err)
		}
		fileClosed = true
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := s.bindingOps.link(tempPath, s.bindingPath); err != nil {
			if errors.Is(err, os.ErrExist) {
				cleanupErr := s.removeTemporaryBinding(tempPath)
				owner, readErr := s.ClusterBinding(ctx)
				if readErr != nil {
					return errors.Join(cleanupErr, readErr)
				}
				return errors.Join(cleanupErr, s.syncPublishedBinding(), requireClaimOwner(s.bindingPath, id, owner))
			}
			return fmt.Errorf("publish software marker %q: %w", s.bindingPath, err)
		}
		cleanupErr := s.removeTemporaryBinding(tempPath)
		directoryErr := s.syncBindingDirectory()
		return errors.Join(cleanupErr, directoryErr)
	})
}

func (s *Software) removeTemporaryBinding(path string) error {
	if err := s.bindingOps.remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove temporary software marker %q: %w", path, err)
	}
	return nil
}

func (s *Software) syncPublishedBinding() error {
	file, err := s.bindingOps.open(s.bindingPath)
	if err != nil {
		return fmt.Errorf("open published software marker %q: %w", s.bindingPath, err)
	}
	if err := s.bindingOps.sync(file); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync published software marker %q: %w", s.bindingPath, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close published software marker %q: %w", s.bindingPath, err)
	}
	return s.syncBindingDirectory()
}

func (s *Software) syncBindingDirectory() error {
	directory := filepath.Dir(s.bindingPath)
	dir, err := s.bindingOps.open(directory)
	if err != nil {
		return fmt.Errorf("open software marker directory %q: %w", directory, err)
	}
	if err := s.bindingOps.sync(dir); err != nil {
		_ = dir.Close()
		return fmt.Errorf("sync software marker directory %q: %w", directory, err)
	}
	if err := dir.Close(); err != nil {
		return fmt.Errorf("close software marker directory %q: %w", directory, err)
	}
	return nil
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
