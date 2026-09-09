package backend

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/cometbft/cometbft/crypto"
	cmtjson "github.com/cometbft/cometbft/libs/json"
	"github.com/cometbft/cometbft/privval"
)

const softwareBindingSuffix = ".cosmosigner-cluster.json"

type softwareOperationHooks struct {
	afterLock func()
}

func resolveExistingSoftwareKeyPath(keyFile string) (string, error) {
	if keyFile == "" {
		return "", fmt.Errorf("software backend requires a key file")
	}
	absPath, err := filepath.Abs(keyFile)
	if err != nil {
		return "", fmt.Errorf("resolve key file path: %w", err)
	}
	canonicalPath, err := filepath.EvalSymlinks(absPath)
	if err != nil {
		return "", fmt.Errorf("resolve key file %q: %w", keyFile, err)
	}
	return canonicalPath, nil
}

func resolveProvisionSoftwareKeyPath(keyFile string) (string, error) {
	if keyFile == "" {
		return "", fmt.Errorf("software backend requires --key-file")
	}
	absPath, err := filepath.Abs(keyFile)
	if err != nil {
		return "", fmt.Errorf("resolve software key path: %w", err)
	}
	directory := filepath.Dir(absPath)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", fmt.Errorf("create key dir: %w", err)
	}
	canonicalPath, err := filepath.EvalSymlinks(absPath)
	if err == nil {
		return canonicalPath, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("resolve software key %q: %w", keyFile, err)
	}
	info, lstatErr := os.Lstat(absPath)
	if lstatErr == nil && info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("resolve software key %q: dangling leaf symlink", keyFile)
	}
	if lstatErr != nil && !errors.Is(lstatErr, os.ErrNotExist) {
		return "", fmt.Errorf("inspect software key %q: %w", keyFile, lstatErr)
	}
	canonicalDirectory, err := filepath.EvalSymlinks(directory)
	if err != nil {
		return "", fmt.Errorf("resolve software key directory %q: %w", directory, err)
	}
	return filepath.Join(canonicalDirectory, filepath.Base(absPath)), nil
}

func loadSoftwarePrivateKey(canonicalPath string) (crypto.PrivKey, error) {
	file, err := os.Open(canonicalPath)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	defer file.Close()
	if err := validateSoftwareKeyFile(file, canonicalPath); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	var pvKey privval.FilePVKey
	if err := cmtjson.Unmarshal(data, &pvKey); err != nil {
		return nil, fmt.Errorf("parse key file %q: %w", canonicalPath, err)
	}
	if pvKey.PrivKey == nil {
		return nil, fmt.Errorf("key file %q has no priv_key", canonicalPath)
	}
	if pvKey.PubKey != nil && !bytes.Equal(pvKey.PrivKey.PubKey().Bytes(), pvKey.PubKey.Bytes()) {
		return nil, fmt.Errorf("key file %q is corrupt: pub_key does not match priv_key", canonicalPath)
	}
	return pvKey.PrivKey, nil
}

func validateSoftwareKeyFile(file *os.File, path string) error {
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat software key %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("software key %q is not a regular file", path)
	}
	links, err := softwareFileLinkCount(file)
	if err != nil {
		return fmt.Errorf("inspect hard links for software key %q: %w", path, err)
	}
	if links != 1 {
		return fmt.Errorf("software key %q has multiple hard links (%d)", path, links)
	}
	return nil
}

// ProvisionSoftwareKey atomically creates or replaces an unclaimed software key.
func ProvisionSoftwareKey(ctx context.Context, keyFile string, overwrite bool) (crypto.PubKey, error) {
	return provisionSoftwareKey(ctx, keyFile, overwrite, softwareOperationHooks{})
}

func provisionSoftwareKey(ctx context.Context, keyFile string, overwrite bool, hooks softwareOperationHooks) (crypto.PubKey, error) {
	canonicalPath, err := resolveProvisionSoftwareKeyPath(keyFile)
	if err != nil {
		return nil, err
	}
	var pub crypto.PubKey
	err = withSoftwareKeyLock(ctx, canonicalPath, hooks, func() error {
		bindingPath := canonicalPath + softwareBindingSuffix
		if _, err := os.Lstat(bindingPath); err == nil {
			return fmt.Errorf("refusing to provision software key with binding marker %q", bindingPath)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect software binding marker %q: %w", bindingPath, err)
		}

		file, err := os.Open(canonicalPath)
		switch {
		case err == nil:
			validationErr := validateSoftwareKeyFile(file, canonicalPath)
			closeErr := file.Close()
			if validationErr != nil {
				return validationErr
			}
			if closeErr != nil {
				return fmt.Errorf("close software key %q: %w", canonicalPath, closeErr)
			}
			if !overwrite {
				return fmt.Errorf("%s already exists (use --overwrite)", keyFile)
			}
		case errors.Is(err, os.ErrNotExist):
		default:
			return fmt.Errorf("inspect software key %q: %w", canonicalPath, err)
		}

		pv := privval.GenFilePV(canonicalPath, "")
		data, err := cmtjson.MarshalIndent(pv.Key, "", "  ")
		if err != nil {
			return fmt.Errorf("encode software key: %w", err)
		}
		if err := writeSoftwareKeyAtomically(ctx, canonicalPath, data); err != nil {
			return err
		}
		pub = pv.Key.PubKey
		return nil
	})
	return pub, err
}

func writeSoftwareKeyAtomically(ctx context.Context, path string, data []byte) error {
	directory := filepath.Dir(path)
	file, err := os.CreateTemp(directory, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary software key in %q: %w", directory, err)
	}
	tempPath := file.Name()
	closed := false
	defer func() {
		if !closed {
			_ = file.Close()
		}
		_ = os.Remove(tempPath)
	}()
	if err := file.Chmod(0o600); err != nil {
		return fmt.Errorf("set temporary software key permissions: %w", err)
	}
	written, err := file.Write(data)
	if err != nil {
		return fmt.Errorf("write temporary software key %q: %w", tempPath, err)
	}
	if written != len(data) {
		return fmt.Errorf("write temporary software key %q: %w", tempPath, io.ErrShortWrite)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync temporary software key %q: %w", tempPath, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close temporary software key %q: %w", tempPath, err)
	}
	closed = true
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("publish software key %q: %w", path, err)
	}
	dir, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open software key directory %q: %w", directory, err)
	}
	if err := dir.Sync(); err != nil {
		_ = dir.Close()
		return fmt.Errorf("sync software key directory %q: %w", directory, err)
	}
	if err := dir.Close(); err != nil {
		return fmt.Errorf("close software key directory %q: %w", directory, err)
	}
	return nil
}

func withSoftwareKeyLock(ctx context.Context, canonicalPath string, hooks softwareOperationHooks, operation func() error) (resultErr error) {
	unlock, err := acquireSoftwareKeyLock(ctx, canonicalPath)
	if err != nil {
		return err
	}
	defer func() {
		resultErr = errors.Join(resultErr, unlock())
	}()
	if hooks.afterLock != nil {
		hooks.afterLock()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return operation()
}
