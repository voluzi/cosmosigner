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
	"strings"

	"github.com/google/tink/go/kwp/subtle"
	vaultapi "github.com/hashicorp/vault/api"
)

// Vault returns this only after confirming the selected version already contains private material.
const vaultPrivateKeyAlreadyImported = "private key imported, key version cannot be updated"

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

	// Creating a Transit key is create-only. A matching existing version is accepted only after a
	// signing probe succeeds or Vault's version-import endpoint proves or completes private material.
	// A different existing identity is never overwritten.
	existing, selectedVersion, minimumSigningVersion, exists, err := (&Vault{
		client: client, mount: cfg.Mount, keyName: cfg.KeyName, requestedKeyVersion: cfg.KeyVersion,
	}).fetchPubKeyIfExists(false)
	if err != nil {
		return err
	}
	if exists {
		if bytes.Equal(existing.Bytes(), wantPublicKey) {
			var signErr error
			if selectedVersion >= minimumSigningVersion {
				vault := &Vault{
					client: client, mount: cfg.Mount, keyName: cfg.KeyName,
					pub: existing, keyVersion: selectedVersion,
				}
				if signErr = vault.verifySigningKey(); signErr == nil {
					return nil
				}
			}

			ciphertext, err := wrapVaultImportKey(client, cfg.Mount, pkcs8DER)
			if err != nil {
				return err
			}
			_, err = client.Logical().Write(cfg.Mount+"/keys/"+cfg.KeyName+"/import_version", map[string]any{
				"ciphertext":    ciphertext,
				"hash_function": "SHA256",
				"version":       selectedVersion,
			})
			if err == nil || strings.Contains(err.Error(), vaultPrivateKeyAlreadyImported) {
				return nil
			}
			if signErr != nil {
				return fmt.Errorf("transit key %q version %d has the expected public key but failed both the signing probe (%v) and private-key completion: %w", cfg.KeyName, selectedVersion, signErr, err)
			}
			return fmt.Errorf("prove transit key %q version %d has private signing material: %w", cfg.KeyName, selectedVersion, err)
		}
		return fmt.Errorf("transit key %q version %d already exists with a different public key; use a new key name instead of overwriting a validator identity", cfg.KeyName, selectedVersion)
	}
	if cfg.KeyVersion < 0 || cfg.KeyVersion > 1 {
		return fmt.Errorf("new Vault imports create key version 1; requested version %d", cfg.KeyVersion)
	}

	ciphertext, err := wrapVaultImportKey(client, cfg.Mount, pkcs8DER)
	if err != nil {
		return err
	}

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

func wrapVaultImportKey(client *vaultapi.Client, mount string, pkcs8DER []byte) (string, error) {
	secret, err := client.Logical().Read(mount + "/wrapping_key")
	if err != nil {
		return "", fmt.Errorf("read transit wrapping key: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return "", fmt.Errorf("transit wrapping key not available (Vault >= 1.12 required)")
	}
	pemStr, _ := secret.Data["public_key"].(string)
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return "", fmt.Errorf("decode wrapping key PEM")
	}
	wrappingPublicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse wrapping key: %w", err)
	}
	rsaPub, ok := wrappingPublicKey.(*rsa.PublicKey)
	if !ok {
		return "", fmt.Errorf("wrapping key is not RSA (%T)", wrappingPublicKey)
	}

	// An ephemeral AES-256 key wraps the PKCS#8 material (AES-KWP).
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		return "", fmt.Errorf("generate ephemeral key: %w", err)
	}
	kwp, err := subtle.NewKWP(aesKey)
	if err != nil {
		return "", fmt.Errorf("init AES-KWP: %w", err)
	}
	wrappedTarget, err := kwp.Wrap(pkcs8DER)
	if err != nil {
		return "", fmt.Errorf("wrap key material: %w", err)
	}

	// RSA-OAEP-SHA256 wraps the ephemeral AES key; ciphertext is the concat.
	wrappedAES, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPub, aesKey, nil)
	if err != nil {
		return "", fmt.Errorf("wrap ephemeral key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(append(wrappedAES, wrappedTarget...)), nil
}
