// Package server wires the cometbft privval endpoints to the gated signer and
// gates the node connections behind raft leadership.
package server

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/crypto/ed25519"
	cmtjson "github.com/cometbft/cometbft/libs/json"
)

// LoadOrGenConnKey loads the SecretConnection identity key from path, or
// generates and persists a new one (0600). This key authenticates the signer's
// side of the encrypted privval handshake and is DISTINCT from the consensus
// key — it never signs blocks.
func LoadOrGenConnKey(path string) (crypto.PrivKey, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		var key crypto.PrivKey
		if err := cmtjson.Unmarshal(data, &key); err != nil {
			return nil, fmt.Errorf("parse conn key %q: %w", path, err)
		}
		return key, nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read conn key %q: %w", path, err)
	}

	var key crypto.PrivKey = ed25519.GenPrivKey()
	out, err := cmtjson.Marshal(key)
	if err != nil {
		return nil, fmt.Errorf("marshal conn key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create conn key dir: %w", err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		return nil, fmt.Errorf("write conn key %q: %w", path, err)
	}
	return key, nil
}
