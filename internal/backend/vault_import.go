package backend

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"

	"github.com/google/tink/go/kwp/subtle"
)

// VaultImportKey imports a PKCS#8 DER ed25519 private key into the Vault
// Transit engine under cfg.KeyName (non-exportable) using the BYOK flow:
// fetch the mount's RSA wrapping key, wrap the key material with an ephemeral
// AES key (CKM_RSA_AES_KEY_WRAP: AES-KWP for the target, RSA-OAEP-SHA256 for
// the AES key), and post the combined ciphertext to keys/<name>/import.
func VaultImportKey(cfg VaultConfig, pkcs8DER []byte) error {
	if cfg.Mount == "" {
		cfg.Mount = "transit"
	}
	client, err := NewVaultClient(cfg)
	if err != nil {
		return err
	}
	parsed, err := x509.ParsePKCS8PrivateKey(pkcs8DER)
	if err != nil {
		return fmt.Errorf("parse PKCS#8 private key: %w", err)
	}
	privateKey, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return fmt.Errorf("PKCS#8 private key is %T, want ed25519", parsed)
	}
	wantPublicKey := privateKey.Public().(ed25519.PublicKey)

	// Import is a create-only Vault operation. Treat an existing identical version as success so a
	// controller can safely retry after Vault accepted the key but its status write was interrupted.
	// A different existing identity is never overwritten.
	existing, selectedVersion, exists, err := (&Vault{
		client: client, mount: cfg.Mount, keyName: cfg.KeyName, requestedKeyVersion: cfg.KeyVersion,
	}).fetchPubKeyIfExists()
	if err != nil {
		return err
	}
	if exists {
		if bytes.Equal(existing.Bytes(), wantPublicKey) {
			return nil
		}
		return fmt.Errorf("transit key %q version %d already exists with a different public key; use a new key name instead of overwriting a validator identity", cfg.KeyName, selectedVersion)
	}
	if cfg.KeyVersion < 0 || cfg.KeyVersion > 1 {
		return fmt.Errorf("new Vault imports create key version 1; requested version %d", cfg.KeyVersion)
	}

	// 1. The mount's RSA-4096 wrapping public key.
	secret, err := client.Logical().Read(cfg.Mount + "/wrapping_key")
	if err != nil {
		return fmt.Errorf("read transit wrapping key: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return fmt.Errorf("transit wrapping key not available (Vault >= 1.12 required)")
	}
	pemStr, _ := secret.Data["public_key"].(string)
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return fmt.Errorf("decode wrapping key PEM")
	}
	wrappingPublicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse wrapping key: %w", err)
	}
	rsaPub, ok := wrappingPublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("wrapping key is not RSA (%T)", wrappingPublicKey)
	}

	// 2. Ephemeral AES-256 key wraps the PKCS#8 material (AES-KWP).
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		return fmt.Errorf("generate ephemeral key: %w", err)
	}
	kwp, err := subtle.NewKWP(aesKey)
	if err != nil {
		return fmt.Errorf("init AES-KWP: %w", err)
	}
	wrappedTarget, err := kwp.Wrap(pkcs8DER)
	if err != nil {
		return fmt.Errorf("wrap key material: %w", err)
	}

	// 3. RSA-OAEP-SHA256 wraps the ephemeral AES key; ciphertext is the concat.
	wrappedAES, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPub, aesKey, nil)
	if err != nil {
		return fmt.Errorf("wrap ephemeral key: %w", err)
	}
	ciphertext := base64.StdEncoding.EncodeToString(append(wrappedAES, wrappedTarget...))

	// 4. Import as a non-exportable ed25519 key.
	if _, err := client.Logical().Write(cfg.Mount+"/keys/"+cfg.KeyName+"/import", map[string]any{
		"ciphertext":    ciphertext,
		"type":          "ed25519",
		"hash_function": "SHA256",
		"exportable":    false,
	}); err != nil {
		return fmt.Errorf("transit import: %w", err)
	}
	return nil
}
