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

type fileBinding struct {
	kind           string
	bindingPath    string
	lockPath       string
	bindingOps     softwareBindingOps
	operationHooks softwareOperationHooks
	publicKey      crypto.PubKey
}

func (s *fileBinding) read(ctx context.Context) (string, error) {
	if s.bindingPath == "" {
		return "", ErrBindingUnsupported
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	data, err := os.ReadFile(s.bindingPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("%w: "+s.kind+" marker %q", ErrBindingUnclaimed, s.bindingPath)
		}
		return "", fmt.Errorf("%w: read "+s.kind+" marker %q: %v", ErrBindingUnreadable, s.bindingPath, err)
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}

	var record softwareBindingRecord
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return "", fmt.Errorf("%w: decode "+s.kind+" marker %q: %v", ErrBindingCorrupt, s.bindingPath, err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return "", fmt.Errorf("%w: decode "+s.kind+" marker %q: %v", ErrBindingCorrupt, s.bindingPath, err)
	}
	if record.Version != 1 {
		return "", fmt.Errorf("%w: "+s.kind+" marker %q has version %d", ErrBindingCorrupt, s.bindingPath, record.Version)
	}
	if err := clusterid.Validate(record.ClusterID); err != nil {
		return "", fmt.Errorf("%w: "+s.kind+" marker %q has invalid cluster ID: %v", ErrBindingCorrupt, s.bindingPath, err)
	}
	pub := s.publicKey
	wantPublicKey := base64.StdEncoding.EncodeToString(pub.Bytes())
	if record.PublicKey != wantPublicKey {
		return "", fmt.Errorf("%w: "+s.kind+" marker %q belongs to different key material", ErrBindingCorrupt, s.bindingPath)
	}
	return record.ClusterID, nil
}

func (s *fileBinding) claim(ctx context.Context, id string, precheck func() error) error {
	if s.bindingPath == "" {
		return ErrBindingUnsupported
	}
	if err := clusterid.Validate(id); err != nil {
		return fmt.Errorf("invalid cluster ID: %w", err)
	}
	return withSoftwareKeyLock(ctx, s.lockPath, s.operationHooks, func() error {
		if err := precheck(); err != nil {
			return err
		}

		owner, err := s.read(ctx)
		switch {
		case err == nil:
			return errors.Join(s.syncPublishedBinding(), requireClaimOwner(s.bindingPath, id, owner))
		case !errors.Is(err, ErrBindingUnclaimed):
			return err
		}

		pub := s.publicKey
		data, err := json.Marshal(softwareBindingRecord{
			Version: 1, ClusterID: id, PublicKey: base64.StdEncoding.EncodeToString(pub.Bytes()),
		})
		if err != nil {
			return fmt.Errorf("encode "+s.kind+" marker: %w", err)
		}
		data = append(data, '\n')

		directory := filepath.Dir(s.bindingPath)
		file, err := s.bindingOps.createTemp(directory, "."+filepath.Base(s.bindingPath)+".tmp-*")
		if err != nil {
			return fmt.Errorf("create temporary "+s.kind+" marker in %q: %w", directory, err)
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
			return fmt.Errorf("write temporary "+s.kind+" marker %q: %w", tempPath, err)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := s.bindingOps.sync(file); err != nil {
			return fmt.Errorf("sync temporary "+s.kind+" marker %q: %w", tempPath, err)
		}
		if err := file.Close(); err != nil {
			return fmt.Errorf("close temporary "+s.kind+" marker %q: %w", tempPath, err)
		}
		fileClosed = true
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := s.bindingOps.link(tempPath, s.bindingPath); err != nil {
			if errors.Is(err, os.ErrExist) {
				cleanupErr := s.removeTemporaryBinding(tempPath)
				owner, readErr := s.read(ctx)
				if readErr != nil {
					return errors.Join(cleanupErr, readErr)
				}
				return errors.Join(cleanupErr, s.syncPublishedBinding(), requireClaimOwner(s.bindingPath, id, owner))
			}
			return fmt.Errorf("publish "+s.kind+" marker %q: %w", s.bindingPath, err)
		}
		cleanupErr := s.removeTemporaryBinding(tempPath)
		directoryErr := s.syncBindingDirectory()
		return errors.Join(cleanupErr, directoryErr)
	})
}

func (s *fileBinding) removeTemporaryBinding(path string) error {
	if err := s.bindingOps.remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove temporary "+s.kind+" marker %q: %w", path, err)
	}
	return nil
}

func (s *fileBinding) syncPublishedBinding() error {
	file, err := s.bindingOps.open(s.bindingPath)
	if err != nil {
		return fmt.Errorf("open published "+s.kind+" marker %q: %w", s.bindingPath, err)
	}
	if err := s.bindingOps.sync(file); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync published "+s.kind+" marker %q: %w", s.bindingPath, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close published "+s.kind+" marker %q: %w", s.bindingPath, err)
	}
	return s.syncBindingDirectory()
}

func (s *fileBinding) syncBindingDirectory() error {
	directory := filepath.Dir(s.bindingPath)
	dir, err := s.bindingOps.open(directory)
	if err != nil {
		return fmt.Errorf("open "+s.kind+" marker directory %q: %w", directory, err)
	}
	if err := s.bindingOps.sync(dir); err != nil {
		_ = dir.Close()
		return fmt.Errorf("sync "+s.kind+" marker directory %q: %w", directory, err)
	}
	if err := dir.Close(); err != nil {
		return fmt.Errorf("close "+s.kind+" marker directory %q: %w", directory, err)
	}
	return nil
}

// resolveBindingPath canonicalises the marker's directory, which must exist, so the marker
// is compared and locked by its real location.
func resolveBindingPath(bindingFile, kind string) (string, error) {
	absPath, err := filepath.Abs(bindingFile)
	if err != nil {
		return "", fmt.Errorf("resolve "+kind+" binding file: %w", err)
	}
	directory, err := filepath.EvalSymlinks(filepath.Dir(absPath))
	if err != nil {
		return "", fmt.Errorf("resolve "+kind+" binding directory %q: %w", filepath.Dir(absPath), err)
	}
	bindingPath := filepath.Join(directory, filepath.Base(absPath))
	// The marker is published with link(2), which never follows a symlink: a symlink at the marker
	// path, dangling or not, would read as unclaimed yet make every claim fail.
	if info, err := os.Lstat(bindingPath); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf(kind+" binding file %q must not be a symlink", bindingFile)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("inspect "+kind+" binding file %q: %w", bindingFile, err)
	}
	return bindingPath, nil
}
