//go:build pkcs11 && cgo && pkcs11_integration

package backend

import (
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	p11 "github.com/miekg/pkcs11"
	"github.com/stretchr/testify/require"
)

const pkcs11EdwardsKeyPairGen = 0x1055

// These tests create and replace keys. Use a disposable SoftHSM token only.
func integrationPKCS11(t *testing.T) (PKCS11Config, *p11.Ctx, uint, uint) {
	t.Helper()
	module := os.Getenv("COSMOSIGNER_PKCS11_MODULE")
	label := os.Getenv("COSMOSIGNER_PKCS11_TOKEN_LABEL")
	pinFile := os.Getenv("COSMOSIGNER_PKCS11_PIN_FILE")
	require.NotEmpty(t, module, "integration tests require COSMOSIGNER_PKCS11_MODULE")
	require.NotEmpty(t, label, "integration tests require COSMOSIGNER_PKCS11_TOKEN_LABEL")
	require.NotEmpty(t, pinFile, "integration tests require COSMOSIGNER_PKCS11_PIN_FILE")
	p := p11.New(module)
	require.NotNil(t, p)
	err := p.Initialize()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, p.Finalize()); p.Destroy() })
	slots, err := p.GetSlotList(true)
	require.NoError(t, err)
	var slot uint
	found := false
	for _, s := range slots {
		info, e := p.GetTokenInfo(s)
		require.NoError(t, e)
		if info.Label == label {
			require.False(t, found, "ambiguous token")
			slot = s
			found = true
		}
	}
	require.True(t, found, "test token is missing")
	sh, err := p.OpenSession(slot, p11.CKF_SERIAL_SESSION|p11.CKF_RW_SESSION)
	require.NoError(t, err)
	pin, err := os.ReadFile(pinFile)
	require.NoError(t, err)
	err = p.Login(sh, p11.CKU_USER, string(bytesTrimPIN(pin)))
	if err != nil {
		require.Equal(t, p11.Error(p11.CKR_USER_ALREADY_LOGGED_IN), err)
	}
	t.Cleanup(func() {
		err := p.CloseSession(sh)
		if err != nil {
			require.Contains(t, []error{p11.Error(p11.CKR_SESSION_HANDLE_INVALID), p11.Error(p11.CKR_SESSION_CLOSED)}, err)
		}
	})
	cfg := PKCS11Config{Module: module, TokenLabel: label, PINFile: pinFile, BindingFile: filepath.Join(t.TempDir(), "binding"), KeyLabel: t.Name()}
	return cfg, p, slot, uint(sh)
}
func bytesTrimPIN(pin []byte) []byte {
	for len(pin) > 0 && (pin[len(pin)-1] == '\n' || pin[len(pin)-1] == '\r') {
		pin = pin[:len(pin)-1]
	}
	return pin
}
func generateIntegrationKey(t *testing.T, p *p11.Ctx, sh uint, label string, id []byte, params []byte, mechanism, keyType uint) (p11.ObjectHandle, p11.ObjectHandle, error) {
	t.Helper()
	pub, priv, err := p.GenerateKeyPair(p11.SessionHandle(sh), []*p11.Mechanism{p11.NewMechanism(mechanism, nil)},
		[]*p11.Attribute{p11.NewAttribute(p11.CKA_TOKEN, true), p11.NewAttribute(p11.CKA_LABEL, label), p11.NewAttribute(p11.CKA_ID, id), p11.NewAttribute(p11.CKA_KEY_TYPE, keyType), p11.NewAttribute(p11.CKA_EC_PARAMS, params), p11.NewAttribute(p11.CKA_VERIFY, true)},
		[]*p11.Attribute{p11.NewAttribute(p11.CKA_TOKEN, true), p11.NewAttribute(p11.CKA_PRIVATE, true), p11.NewAttribute(p11.CKA_LABEL, label), p11.NewAttribute(p11.CKA_ID, id), p11.NewAttribute(p11.CKA_KEY_TYPE, keyType), p11.NewAttribute(p11.CKA_SIGN, true), p11.NewAttribute(p11.CKA_SENSITIVE, true), p11.NewAttribute(p11.CKA_EXTRACTABLE, false)})
	return pub, priv, err
}
func TestPKCS11IntegrationSigningRecoveryAndBinding(t *testing.T) {
	cfg, p, slot, sh := integrationPKCS11(t)
	id := []byte(t.Name())
	_, _, err := generateIntegrationKey(t, p, sh, cfg.KeyLabel, id, append([]byte{19, 12}, []byte("edwards25519")...), pkcs11EdwardsKeyPairGen, pkcs11Edwards)
	require.NoError(t, err)
	cleanupIntegrationKeys(t, p, slot, cfg)
	a, err := NewPKCS11(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, a.Close()) })
	b, err := NewPKCS11(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, b.Close()) })
	requireSignDeterminism(t, a, b)
	require.NoError(t, a.VerifyCanSign(t.Context()))
	for _, selector := range []string{"id", "both", "slot"} {
		t.Run(selector, func(t *testing.T) {
			c := cfg
			switch selector {
			case "id":
				c.KeyLabel = ""
				c.KeyID = hex.EncodeToString(id)
			case "both":
				c.KeyID = hex.EncodeToString(id)
			case "slot":
				c.TokenLabel = ""
				c.Slot = &slot
			}
			be, e := NewPKCS11(c)
			require.NoError(t, e)
			defer be.Close()
			require.NoError(t, be.VerifyCanSign(t.Context()))
		})
	}
	var wg sync.WaitGroup
	errs := make([]error, 2)
	wg.Go(func() { errs[0] = a.ClaimCluster(t.Context(), clusterA) })
	wg.Go(func() { errs[1] = b.ClaimCluster(t.Context(), clusterB) })
	wg.Wait()
	require.True(t, (errs[0] == nil && errors.Is(errs[1], ErrBindingMismatch)) || (errs[1] == nil && errors.Is(errs[0], ErrBindingMismatch)))
	owner, err := a.ClusterBinding(t.Context())
	require.NoError(t, err)
	require.NoError(t, b.ClaimCluster(t.Context(), owner))
	require.NoError(t, p.CloseAllSessions(slot))
	require.NoError(t, a.VerifyCanSign(t.Context()))
	requireSignDeterminism(t, a, b)
	require.NoError(t, a.Close())
	require.NoError(t, b.VerifyCanSign(t.Context()), "closing one backend must not affect another")
	require.NoError(t, b.Close())
	reopened, err := NewPKCS11(cfg)
	require.NoError(t, err)
	defer reopened.Close()
	require.NoError(t, reopened.VerifyCanSign(t.Context()))
}
func TestPKCS11IntegrationReplacedKeyFailsClosed(t *testing.T) {
	cfg, p, slot, sh := integrationPKCS11(t)
	pub, priv, err := generateIntegrationKey(t, p, sh, cfg.KeyLabel, []byte{1}, append([]byte{19, 12}, []byte("edwards25519")...), pkcs11EdwardsKeyPairGen, pkcs11Edwards)
	require.NoError(t, err)
	a, err := NewPKCS11(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, a.Close()) })
	require.NoError(t, a.ClaimCluster(t.Context(), clusterA))
	require.NoError(t, p.DestroyObject(p11.SessionHandle(sh), pub))
	require.NoError(t, p.DestroyObject(p11.SessionHandle(sh), priv))
	_, _, err = generateIntegrationKey(t, p, sh, cfg.KeyLabel, []byte{1}, append([]byte{19, 12}, []byte("edwards25519")...), pkcs11EdwardsKeyPairGen, pkcs11Edwards)
	require.NoError(t, err)
	cleanupIntegrationKeys(t, p, slot, cfg)
	require.NoError(t, p.CloseAllSessions(slot))
	sig, err := a.Sign([]byte("cosmosigner replacement drill - not a consensus message"))
	require.Nil(t, sig)
	require.ErrorContains(t, err, "key changed")
	require.ErrorIs(t, a.ClaimCluster(t.Context(), clusterA), ErrBindingCorrupt)
	replacement, err := NewPKCS11(cfg)
	require.NoError(t, err)
	defer replacement.Close()
	_, err = replacement.ClusterBinding(t.Context())
	require.ErrorIs(t, err, ErrBindingCorrupt)
}
func TestPKCS11IntegrationRejectsOtherCurves(t *testing.T) {
	cfg, p, _, sh := integrationPKCS11(t)
	for _, tc := range []struct {
		name               string
		params             []byte
		mechanism, keyType uint
		optional           bool
		wantError          string
	}{
		{"P256", []byte{6, 8, 42, 134, 72, 206, 61, 3, 1, 7}, p11.CKM_EC_KEY_PAIR_GEN, p11.CKK_EC, false, "matched 0 objects"},
		{"Ed448", append([]byte{19, 10}, []byte("edwards448")...), pkcs11EdwardsKeyPairGen, pkcs11Edwards, true, "parameters are not Ed25519"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := cfg
			c.KeyLabel += tc.name
			pub, priv, err := generateIntegrationKey(t, p, sh, c.KeyLabel, []byte(tc.name), tc.params, tc.mechanism, tc.keyType)
			if err != nil && tc.optional {
				t.Skipf("token cannot generate Ed448: %v", err)
			}
			require.NoError(t, err)
			defer p.DestroyObject(p11.SessionHandle(sh), pub)
			defer p.DestroyObject(p11.SessionHandle(sh), priv)
			be, err := NewPKCS11(c)
			require.Nil(t, be)
			require.ErrorContains(t, err, tc.wantError)
		})
	}
}

func TestPKCS11IntegrationPINFailureSurvivesNewBackend(t *testing.T) {
	module := os.Getenv("COSMOSIGNER_PKCS11_MODULE")
	require.NotEmpty(t, module)
	// Isolate the process-wide module latch from the token used by other tests.
	dir := t.TempDir()
	data, err := os.ReadFile(module)
	require.NoError(t, err)
	moduleCopy := filepath.Join(dir, "softhsm.so")
	require.NoError(t, os.WriteFile(moduleCopy, data, 0600))
	require.NoError(t, os.Mkdir(filepath.Join(dir, "tokens"), 0700))
	conf := filepath.Join(dir, "softhsm2.conf")
	require.NoError(t, os.WriteFile(conf, []byte("directories.tokendir = "+filepath.Join(dir, "tokens")+"\nobjectstore.backend = file\nlog.level = ERROR\n"), 0600))
	t.Setenv("SOFTHSM2_CONF", conf)
	output, err := exec.Command("softhsm2-util", "--init-token", "--free", "--label", "pin-latch-test", "--so-pin", "12345678", "--pin", "123456").CombinedOutput()
	require.NoError(t, err, string(output))
	output, err = exec.Command("pkcs11-tool", "--module", moduleCopy, "--token-label", "pin-latch-test", "--login", "--pin", "123456", "--keypairgen", "--key-type", "EC:edwards25519", "--label", "validator", "--id", "01").CombinedOutput()
	require.NoError(t, err, string(output))
	info, err := os.Stat(moduleCopy)
	require.NoError(t, err)
	retiredPath := filepath.Join(dir, "removed-module.so")
	// Model an inode recycled after a previous module was unloaded and removed.
	pkcs11Modules.Lock()
	pkcs11Modules.files[retiredPath] = info
	pkcs11Modules.Unlock()
	t.Cleanup(func() {
		pkcs11Modules.Lock()
		delete(pkcs11Modules.files, retiredPath)
		pkcs11Modules.Unlock()
	})
	originalPIN := []byte("123456\n")
	pinFile := filepath.Join(dir, "pin")
	require.NoError(t, os.WriteFile(pinFile, originalPIN, 0600))
	cfg := PKCS11Config{Module: moduleCopy, TokenLabel: "pin-latch-test", KeyLabel: "validator", PINFile: pinFile, BindingFile: filepath.Join(dir, "binding")}
	a, err := NewPKCS11(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, a.Close()) })
	require.Equal(t, moduleCopy, a.module.(*nativePKCS11).path)
	alias := filepath.Join(dir, "softhsm-alias.so")
	require.NoError(t, os.Link(moduleCopy, alias))
	aliasCfg := cfg
	aliasCfg.Module = alias
	b, err := NewPKCS11(aliasCfg)
	require.NoError(t, err)
	require.NoError(t, a.Close())
	require.NoError(t, b.VerifyCanSign(t.Context()))
	native := b.module.(*nativePKCS11)
	tokens, err := native.Tokens()
	require.NoError(t, err)
	var slot uint
	for _, token := range tokens {
		if token.label == cfg.TokenLabel {
			slot = token.slot
		}
	}
	require.NoError(t, native.ctx.CloseAllSessions(slot))
	require.NoError(t, os.WriteFile(pinFile, []byte("wrong PIN"), 0600))
	_, err = b.Sign([]byte("cosmosigner PIN latch drill - not a consensus message"))
	require.ErrorContains(t, err, "latched")
	require.NoError(t, b.Close())
	require.NoError(t, os.WriteFile(pinFile, originalPIN, 0600))
	reopened, err := NewPKCS11(cfg)
	if reopened != nil {
		require.NoError(t, reopened.Close())
	}
	require.ErrorContains(t, err, "latched", "correcting the PIN must not bypass the process latch")
	cfg.Module = filepath.Join(dir, "another-module-copy.so")
	require.NoError(t, os.WriteFile(cfg.Module, data, 0600))
	reopened, err = NewPKCS11(cfg)
	if reopened != nil {
		require.NoError(t, reopened.Close())
	}
	require.ErrorContains(t, err, "latched", "a copied module must not bypass the token's process latch")
}

func cleanupIntegrationKeys(t *testing.T, p *p11.Ctx, slot uint, cfg PKCS11Config) {
	t.Helper()
	t.Cleanup(func() {
		session, err := p.OpenSession(slot, p11.CKF_SERIAL_SESSION|p11.CKF_RW_SESSION)
		require.NoError(t, err)
		defer p.CloseSession(session)
		pin, err := os.ReadFile(cfg.PINFile)
		require.NoError(t, err)
		err = p.Login(session, p11.CKU_USER, string(bytesTrimPIN(pin)))
		if err != nil {
			require.Equal(t, p11.Error(p11.CKR_USER_ALREADY_LOGGED_IN), err)
		}
		// Object handles belong to sessions; reacquire after CloseAllSessions instead of reusing them.
		require.NoError(t, p.FindObjectsInit(session, []*p11.Attribute{p11.NewAttribute(p11.CKA_LABEL, cfg.KeyLabel)}))
		objects, _, err := p.FindObjects(session, 100)
		require.NoError(t, err)
		require.NoError(t, p.FindObjectsFinal(session))
		for _, object := range objects {
			require.NoError(t, p.DestroyObject(session, object))
		}
	})
}
