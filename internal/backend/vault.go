package backend

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/crypto/ed25519"
	vaultapi "github.com/hashicorp/vault/api"
)

// VaultConfig configures the Vault Transit backend.
type VaultConfig struct {
	Address   string `yaml:"address"     env:"COSMOSIGNER_VAULT_ADDR"`
	TokenFile string `yaml:"token_file"  env:"COSMOSIGNER_VAULT_TOKEN_FILE"`
	Mount     string `yaml:"mount"       env:"COSMOSIGNER_VAULT_MOUNT" default:"transit"` // transit mount path
	KeyName   string `yaml:"key_name"    env:"COSMOSIGNER_VAULT_KEY"`                     // transit key name
	Namespace string `yaml:"namespace"   env:"COSMOSIGNER_VAULT_NAMESPACE"`
	TLSCACert string `yaml:"tls_ca_cert" env:"COSMOSIGNER_VAULT_CA_CERT"`
}

// Vault signs via the Vault Transit engine. The consensus key is created
// non-exportable inside Vault and never leaves it; only signatures cross the
// wire. The public key is fetched once and cached.
type Vault struct {
	client    *vaultapi.Client
	mount     string
	keyName   string
	tokenFile string
	pub       crypto.PubKey
	// keyVersion pins Sign to the version the cached pubkey belongs to, so a
	// transit key rotation cannot silently switch signing to a new key the
	// node does not know.
	keyVersion int

	stopRenew chan struct{}
	stopOnce  sync.Once
}

// NewVault connects to Vault, caches the public key, and starts token renewal.
func NewVault(cfg VaultConfig) (*Vault, error) {
	if cfg.Mount == "" {
		cfg.Mount = "transit"
	}
	if cfg.KeyName == "" {
		return nil, fmt.Errorf("vault backend requires a key name")
	}
	if cfg.TokenFile == "" {
		return nil, fmt.Errorf("vault backend requires a token file")
	}

	client, err := NewVaultClient(cfg)
	if err != nil {
		return nil, err
	}

	v := &Vault{client: client, mount: cfg.Mount, keyName: cfg.KeyName, tokenFile: cfg.TokenFile, stopRenew: make(chan struct{})}
	pub, version, err := v.fetchPubKey()
	if err != nil {
		return nil, err
	}
	v.pub = pub
	v.keyVersion = version
	go v.renewLoop()
	return v, nil
}

// NewVaultClient builds an authenticated Vault client from cfg (token read from
// the token file). Exposed so CLI key-management commands can reuse it.
func NewVaultClient(cfg VaultConfig) (*vaultapi.Client, error) {
	vc := vaultapi.DefaultConfig()
	if cfg.Address != "" {
		vc.Address = cfg.Address
	}
	if cfg.TLSCACert != "" {
		if err := vc.ConfigureTLS(&vaultapi.TLSConfig{CACert: cfg.TLSCACert}); err != nil {
			return nil, fmt.Errorf("configure TLS: %w", err)
		}
	}
	client, err := vaultapi.NewClient(vc)
	if err != nil {
		return nil, fmt.Errorf("new vault client: %w", err)
	}
	if cfg.Namespace != "" {
		client.SetNamespace(cfg.Namespace)
	}
	token, err := os.ReadFile(cfg.TokenFile)
	if err != nil {
		return nil, fmt.Errorf("read token file: %w", err)
	}
	client.SetToken(strings.TrimSpace(string(token)))
	return client, nil
}

func (v *Vault) PubKey() (crypto.PubKey, error) { return v.pub, nil }

// VerifyCanSign checks at startup that the token can actually perform the
// signing the running signer needs, so a misconfigured policy or a doomed token
// fails fast here instead of at the first vote — or at renew time. It verifies
// the `update` capability on transit/sign/<key> and that the token can be kept
// alive (renewable, or non-expiring). Read access to the key is already proven
// by the public-key fetch in NewVault.
func (v *Vault) VerifyCanSign() error {
	signPath := fmt.Sprintf("%s/sign/%s", v.mount, v.keyName)
	caps, err := v.client.Sys().CapabilitiesSelf(signPath)
	if err != nil {
		return fmt.Errorf("check token capabilities on %s: %w", signPath, err)
	}
	if !hasCapability(caps, "update") {
		return fmt.Errorf("vault token lacks 'update' on %s (capabilities: %v) — it cannot sign", signPath, caps)
	}

	secret, err := v.client.Auth().Token().LookupSelf()
	if err != nil {
		return fmt.Errorf("look up vault token: %w", err)
	}
	ttl, _ := secret.TokenTTL()
	renewable, _ := secret.TokenIsRenewable()
	if ttl > 0 && !renewable {
		return fmt.Errorf("vault token has a finite TTL (%s) and is not renewable; cosmosigner cannot keep it alive — use a renewable or periodic token", ttl)
	}
	return nil
}

func hasCapability(caps []string, want string) bool {
	for _, c := range caps {
		if c == want || c == "root" {
			return true
		}
	}
	return false
}

func (v *Vault) Sign(signBytes []byte) ([]byte, error) {
	secret, err := v.client.Logical().Write(
		fmt.Sprintf("%s/sign/%s", v.mount, v.keyName),
		map[string]any{
			"input":       base64.StdEncoding.EncodeToString(signBytes),
			"key_version": v.keyVersion,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("transit sign: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("empty transit sign response")
	}
	sigField, ok := secret.Data["signature"].(string)
	if !ok {
		return nil, fmt.Errorf("transit sign response missing signature")
	}
	return parseTransitSignature(sigField)
}

func (v *Vault) Close() error {
	v.stopOnce.Do(func() { close(v.stopRenew) })
	return nil
}

func (v *Vault) fetchPubKey() (crypto.PubKey, int, error) {
	secret, err := v.client.Logical().Read(fmt.Sprintf("%s/keys/%s", v.mount, v.keyName))
	if err != nil {
		return nil, 0, fmt.Errorf("read transit key: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return nil, 0, fmt.Errorf("transit key %q not found", v.keyName)
	}
	if kt, _ := secret.Data["type"].(string); kt != "" && kt != "ed25519" {
		return nil, 0, fmt.Errorf("transit key %q has type %q, want ed25519", v.keyName, kt)
	}
	latest, err := toInt(secret.Data["latest_version"])
	if err != nil {
		return nil, 0, fmt.Errorf("transit key latest_version: %w", err)
	}
	keys, ok := secret.Data["keys"].(map[string]any)
	if !ok {
		return nil, 0, fmt.Errorf("transit key %q has no keys map", v.keyName)
	}
	verRaw, ok := keys[strconv.Itoa(latest)]
	if !ok {
		return nil, 0, fmt.Errorf("transit key %q missing version %d", v.keyName, latest)
	}
	verMap, ok := verRaw.(map[string]any)
	if !ok {
		return nil, 0, fmt.Errorf("transit key version %d malformed", latest)
	}
	pkB64, ok := verMap["public_key"].(string)
	if !ok || pkB64 == "" {
		return nil, 0, fmt.Errorf("transit key %q has no public_key (must be an ed25519 key)", v.keyName)
	}
	raw, err := base64.StdEncoding.DecodeString(pkB64)
	if err != nil {
		return nil, 0, fmt.Errorf("decode public_key: %w", err)
	}
	if len(raw) != ed25519.PubKeySize {
		return nil, 0, fmt.Errorf("public key size %d, want %d", len(raw), ed25519.PubKeySize)
	}
	pk := make(ed25519.PubKey, ed25519.PubKeySize)
	copy(pk, raw)
	return pk, latest, nil
}

// parseTransitSignature parses Vault's "vault:v<n>:<base64>" signature format
// into the raw 64-byte ed25519 signature.
func parseTransitSignature(s string) ([]byte, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 3 || parts[0] != "vault" {
		return nil, fmt.Errorf("malformed transit signature")
	}
	raw, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}
	if len(raw) != ed25519.SignatureSize {
		return nil, fmt.Errorf("signature size %d, want %d", len(raw), ed25519.SignatureSize)
	}
	return raw, nil
}

func toInt(v any) (int, error) {
	switch n := v.(type) {
	case json.Number:
		i, err := n.Int64()
		return int(i), err
	case float64:
		return int(n), nil
	case int:
		return n, nil
	default:
		return 0, fmt.Errorf("unexpected number type %T", v)
	}
}

// renewLoop keeps the Vault token alive. It tolerates lookup/renew failures and
// non-renewable tokens (e.g. when an external sidecar rotates the token file).
func (v *Vault) renewLoop() {
	for {
		secret, err := v.client.Auth().Token().LookupSelf()
		if err != nil {
			// The current token may have been revoked/expired; if a sidecar
			// rotates the token file, pick up the fresh token from disk.
			if raw, rerr := os.ReadFile(v.tokenFile); rerr == nil {
				if tok := strings.TrimSpace(string(raw)); tok != "" && tok != v.client.Token() {
					v.client.SetToken(tok)
					continue
				}
			}
			if sleepOrStop(v.stopRenew, 30*time.Second) {
				return
			}
			continue
		}
		ttl, _ := secret.TokenTTL()
		renewable, _ := secret.TokenIsRenewable()
		if !renewable || ttl <= 0 {
			if sleepOrStop(v.stopRenew, time.Minute) {
				return
			}
			continue
		}
		wait := max(ttl/2, time.Second)
		if sleepOrStop(v.stopRenew, wait) {
			return
		}
		if _, err := v.client.Auth().Token().RenewSelf(0); err != nil {
			if sleepOrStop(v.stopRenew, 5*time.Second) {
				return
			}
		}
	}
}

// sleepOrStop waits for d or until stop is closed; it returns true if stopped.
func sleepOrStop(stop <-chan struct{}, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-stop:
		return true
	case <-t.C:
		return false
	}
}
