package backend

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"

	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/crypto/ed25519"
)

// PKCS11Config selects a pre-existing token key. The PIN is read only from PINFile.
type PKCS11Config struct {
	Module      string `yaml:"module" env:"COSMOSIGNER_PKCS11_MODULE"`
	TokenLabel  string `yaml:"token_label" env:"COSMOSIGNER_PKCS11_TOKEN_LABEL"`
	Slot        *uint  `yaml:"slot" env:"COSMOSIGNER_PKCS11_SLOT"`
	KeyLabel    string `yaml:"key_label" env:"COSMOSIGNER_PKCS11_KEY_LABEL"`
	KeyID       string `yaml:"key_id" env:"COSMOSIGNER_PKCS11_KEY_ID"`
	PINFile     string `yaml:"pin_file" env:"COSMOSIGNER_PKCS11_PIN_FILE"`
	BindingFile string `yaml:"binding_file" env:"COSMOSIGNER_PKCS11_BINDING_FILE"`
}

func ValidatePKCS11Config(cfg PKCS11Config) error {
	for _, field := range []struct{ name, value string }{{"module", cfg.Module}, {"pin_file", cfg.PINFile}, {"binding_file", cfg.BindingFile}} {
		if field.value == "" {
			return fmt.Errorf("pkcs11 backend requires backend.pkcs11.%s", field.name)
		}
	}
	if (cfg.TokenLabel == "") == (cfg.Slot == nil) {
		return errors.New("pkcs11 backend requires exactly one of token_label or slot")
	}
	if cfg.KeyLabel == "" && cfg.KeyID == "" {
		return errors.New("pkcs11 backend requires key_label or key_id")
	}
	if cfg.KeyID != "" {
		if _, err := hex.DecodeString(cfg.KeyID); err != nil {
			return fmt.Errorf("pkcs11 key_id must be hexadecimal: %w", err)
		}
	}
	return nil
}

// Values added in PKCS#11 v3.0; miekg/pkcs11 v1.1.2 vendors v2.40 headers.
const (
	pkcs11Edwards = 0x40
	pkcs11EdDSA   = 0x1057
)

type pkcs11Error uint

func (e pkcs11Error) Error() string { return fmt.Sprintf("PKCS#11 error 0x%08x", uint(e)) }
func pkcs11Code(err error, codes ...uint) bool {
	var e pkcs11Error
	return errors.As(err, &e) && slices.Contains(codes, uint(e))
}

type pkcs11Token struct {
	slot  uint
	label string
}
type pkcs11Key struct {
	class, keyType uint
	sign           bool
	params, point  []byte
}
type pkcs11Module interface {
	Tokens() ([]pkcs11Token, error)
	Mechanisms(uint) ([]uint, error)
	Open(uint) (uint, error)
	Close(uint) error
	Login(uint, string) error
	Find(uint, bool, PKCS11Config) ([]uint, error)
	Key(uint, uint, bool) (pkcs11Key, error)
	Sign(uint, uint, []byte) ([]byte, error)
}

// PKCS11 serializes one session, including recovery and preflight, under mu.
// Cryptoki calls cannot be cancelled; a hung module stalls signing closed.
type PKCS11 struct {
	mu          sync.Mutex
	cfg         PKCS11Config
	module      pkcs11Module
	release     func() error
	session     uint
	sessionOpen bool
	private     uint
	pub         ed25519.PubKey
	binding     *fileBinding
	pinFailure  error
	closed      bool
}

func newPKCS11(cfg PKCS11Config, module pkcs11Module, release func() error) (*PKCS11, error) {
	b := &PKCS11{cfg: cfg, module: module, release: release}
	if err := ValidatePKCS11Config(cfg); err != nil {
		_ = b.Close()
		return nil, err
	}
	path, err := resolveBindingPath(cfg.BindingFile, "pkcs11")
	if err != nil {
		_ = b.Close()
		return nil, err
	}
	if err := b.reopen(); err != nil {
		_ = b.Close()
		return nil, err
	}
	b.binding = &fileBinding{kind: "pkcs11", bindingPath: path, lockPath: path, bindingOps: defaultSoftwareBindingOps(), publicKey: b.pub}
	return b, nil
}

// reopen must hold mu after construction. Handles never survive a session change.
func (b *PKCS11) reopen() error {
	if b.pinFailure != nil {
		return b.pinFailure
	}
	b.dropSession()
	tokens, err := b.module.Tokens()
	if err != nil {
		return fmt.Errorf("enumerate pkcs11 tokens: %w", err)
	}
	var matches []pkcs11Token
	for _, token := range tokens {
		if (b.cfg.Slot != nil && token.slot == *b.cfg.Slot) || (b.cfg.Slot == nil && token.label == b.cfg.TokenLabel) {
			matches = append(matches, token)
		}
	}
	if len(matches) != 1 {
		return fmt.Errorf("pkcs11 token selector matched %d present tokens, want exactly one", len(matches))
	}
	mechanisms, err := b.module.Mechanisms(matches[0].slot)
	if err != nil {
		return fmt.Errorf("read pkcs11 mechanisms: %w", err)
	}
	if !slices.Contains(mechanisms, pkcs11EdDSA) {
		return errors.New("pkcs11 token does not support CKM_EDDSA")
	}
	pin, err := os.ReadFile(b.cfg.PINFile)
	if err != nil {
		return fmt.Errorf("read pkcs11 pin_file: %w", err)
	}
	defer clear(pin)
	// Only line endings are removed: spaces can be part of a token PIN.
	pinText := strings.TrimRight(string(pin), "\r\n")
	if pinText == "" {
		return errors.New("pkcs11 pin_file is empty")
	}
	b.session, err = b.module.Open(matches[0].slot)
	if err != nil {
		return fmt.Errorf("open pkcs11 session: %w", err)
	}
	b.sessionOpen = true
	err = b.module.Login(b.session, pinText)
	if err != nil && !pkcs11Code(err, 0x100) {
		if pkcs11Code(err, 0xa0, 0xa4) {
			b.pinFailure = fmt.Errorf("pkcs11 PIN failure latched; restart only after correcting token access: %w", err)
		}
		b.dropSession()
		if b.pinFailure != nil {
			return b.pinFailure
		}
		return fmt.Errorf("login pkcs11 session: %w", err)
	}
	private, pub, err := b.keys()
	if err == nil && b.pub != nil && !bytes.Equal(b.pub, pub) {
		err = errors.New("pkcs11 key changed after session recovery")
	}
	if err != nil {
		b.dropSession()
		return err
	}
	b.private = private
	if b.pub == nil {
		b.pub = pub
	}
	return nil
}
func (b *PKCS11) dropSession() {
	if b.sessionOpen {
		_ = b.module.Close(b.session)
		b.sessionOpen = false
	}
	b.private = 0
}

func (b *PKCS11) keys() (uint, ed25519.PubKey, error) {
	var private uint
	var pub ed25519.PubKey
	for _, isPrivate := range []bool{true, false} {
		objects, err := b.module.Find(b.session, isPrivate, b.cfg)
		if err != nil {
			return 0, nil, fmt.Errorf("find pkcs11 key: %w", err)
		}
		kind := "public"
		wantClass := uint(2)
		if isPrivate {
			kind = "private"
			wantClass = 3
		}
		if len(objects) != 1 {
			return 0, nil, fmt.Errorf("pkcs11 %s key selector matched %d objects, want exactly one", kind, len(objects))
		}
		key, err := b.module.Key(b.session, objects[0], isPrivate)
		if err != nil {
			return 0, nil, fmt.Errorf("read pkcs11 %s key: %w", kind, err)
		}
		if key.class != wantClass || key.keyType != pkcs11Edwards || (isPrivate && !key.sign) {
			return 0, nil, fmt.Errorf("pkcs11 %s key must be a signing Ed25519 key", kind)
		}
		if !bytes.Equal(key.params, []byte{6, 3, 43, 101, 112}) && !bytes.Equal(key.params, append([]byte{19, 12}, []byte("edwards25519")...)) {
			return 0, nil, fmt.Errorf("pkcs11 %s key parameters are not Ed25519", kind)
		}
		if isPrivate {
			private = objects[0]
			continue
		}
		point := key.point
		if len(point) == 34 && point[0] == 4 && point[1] == 32 {
			point = point[2:]
		}
		if len(point) != ed25519.PubKeySize {
			return 0, nil, errors.New("pkcs11 public key must be 32 raw bytes or a DER OCTET STRING of 32 bytes")
		}
		pub = append(ed25519.PubKey(nil), point...)
	}
	return private, pub, nil
}

func (b *PKCS11) PubKey() (crypto.PubKey, error) { return append(ed25519.PubKey(nil), b.pub...), nil }
func (b *PKCS11) Sign(msg []byte) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sign(msg)
}
func (b *PKCS11) sign(msg []byte) ([]byte, error) {
	if b.closed {
		return nil, errors.New("pkcs11 backend is closed")
	}
	if b.pinFailure != nil {
		return nil, b.pinFailure
	}
	if !b.sessionOpen {
		if err := b.reopen(); err != nil {
			return nil, err
		}
	}
	sig, err := b.module.Sign(b.session, b.private, msg)
	if pkcs11Code(err, 0xb0, 0xb3, 0x32, 0xe0, 0x101) {
		if err = b.reopen(); err != nil {
			return nil, err
		}
		sig, err = b.module.Sign(b.session, b.private, msg)
		if err != nil {
			b.dropSession()
		}
	}
	if err != nil {
		b.dropSession()
		return nil, fmt.Errorf("pkcs11 sign: %w", err)
	}
	if len(sig) != ed25519.SignatureSize || !b.pub.VerifySignature(msg, sig) {
		return nil, errors.New("pkcs11 returned an invalid Ed25519 signature for the cached public key")
	}
	return append([]byte(nil), sig...), nil
}
func (b *PKCS11) VerifyCanSign(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	probe := []byte("cosmosigner/pkcs11 preflight - not a consensus message")
	first, err := b.sign(probe)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	second, err := b.sign(probe)
	if err != nil {
		return err
	}
	if !bytes.Equal(first, second) {
		return errors.New("pkcs11 Ed25519 signatures are not deterministic")
	}
	return ctx.Err()
}
func (b *PKCS11) ClusterBinding(ctx context.Context) (string, error) { return b.binding.read(ctx) }
func (b *PKCS11) ClaimCluster(ctx context.Context, id string) error {
	return b.binding.claim(ctx, id, func() error {
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.closed {
			return errors.New("pkcs11 backend is closed")
		}
		if b.pinFailure != nil {
			return b.pinFailure
		}
		if !b.sessionOpen {
			if err := b.reopen(); err != nil {
				return fmt.Errorf("%w: %v", ErrBindingCorrupt, err)
			}
		}
		_, pub, err := b.keys()
		if err != nil {
			return fmt.Errorf("%w: validate pkcs11 key before claim: %v", ErrBindingCorrupt, err)
		}
		if !bytes.Equal(b.pub, pub) {
			return fmt.Errorf("%w: pkcs11 key changed before claim", ErrBindingCorrupt)
		}
		return ctx.Err()
	})
}
func (b *PKCS11) bindingResource() string {
	selector := fmt.Sprintf("token %q", b.cfg.TokenLabel)
	if b.cfg.Slot != nil {
		selector = fmt.Sprintf("slot %d", *b.cfg.Slot)
	}
	return fmt.Sprintf("%s (pkcs11 %s key label %q ID %q)", b.binding.bindingPath, selector, b.cfg.KeyLabel, b.cfg.KeyID)
}
func (b *PKCS11) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil
	}
	b.closed = true
	var err error
	if b.sessionOpen {
		err = b.module.Close(b.session)
		b.sessionOpen = false
	}
	// Login state is shared by every session on a token; never log out here.
	if b.release != nil {
		err = errors.Join(err, b.release())
	}
	return err
}
