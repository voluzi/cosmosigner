package backend

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/cometbft/cometbft/crypto"
	cmted25519 "github.com/cometbft/cometbft/crypto/ed25519"
	cmtjson "github.com/cometbft/cometbft/libs/json"
	"github.com/cometbft/cometbft/privval"
)

// LoadKeyFilePKCS8 reads a priv_validator_key.json file and returns the
// private key as PKCS#8 DER (the format KMS/Vault BYOK imports require) along
// with the public key.
//
// CometBFT stores the 64-byte expanded ed25519 key (seed ‖ pubkey); PKCS#8
// wraps only the 32-byte seed, so this extracts the seed and re-encodes it.
func LoadKeyFilePKCS8(path string) ([]byte, crypto.PubKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read key file: %w", err)
	}
	var pvKey privval.FilePVKey
	if err := cmtjson.Unmarshal(data, &pvKey); err != nil {
		return nil, nil, fmt.Errorf("parse key file %q: %w", path, err)
	}
	priv, ok := pvKey.PrivKey.(cmted25519.PrivKey)
	if !ok {
		return nil, nil, fmt.Errorf("key file %q is not ed25519 (%T)", path, pvKey.PrivKey)
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, nil, fmt.Errorf("ed25519 private key size %d, want %d", len(priv), ed25519.PrivateKeySize)
	}

	stdPriv := ed25519.NewKeyFromSeed(priv[:ed25519.SeedSize])

	// The derived public key must match both the expanded key's trailing 32
	// bytes and the pub_key stored in the file — a mismatch means the file is
	// corrupt or hand-edited, and importing it would create a key with a
	// different identity than the operator expects to keep.
	derivedPub := stdPriv.Public().(ed25519.PublicKey)
	if !bytes.Equal(derivedPub, priv[ed25519.SeedSize:]) {
		return nil, nil, fmt.Errorf("key file %q is corrupt: private key halves are inconsistent", path)
	}
	if pvKey.PubKey != nil && !bytes.Equal(derivedPub, pvKey.PubKey.Bytes()) {
		return nil, nil, fmt.Errorf("key file %q is corrupt: pub_key does not match priv_key", path)
	}

	der, err := x509.MarshalPKCS8PrivateKey(stdPriv)
	if err != nil {
		return nil, nil, fmt.Errorf("encode PKCS#8: %w", err)
	}
	return der, priv.PubKey(), nil
}
