package backend

import (
	"bytes"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cometbft/cometbft/crypto/ed25519"
	voi "github.com/oasisprotocol/curve25519-voi/primitives/ed25519"
	"github.com/stretchr/testify/require"
)

type fakePKCS11 struct {
	priv                      ed25519.PrivKey
	tokens                    []pkcs11Token
	mechanisms                []uint
	private, public           pkcs11Key
	privateCount, publicCount int
	opens, logins, closes     int
	loginErr, signErr         error
	signFunc                  func([]byte) ([]byte, error)
	active                    atomic.Int32
	overlap                   atomic.Bool
}

func newFakePKCS11() *fakePKCS11 {
	priv := ed25519.GenPrivKey()
	return &fakePKCS11{priv: priv, tokens: []pkcs11Token{{slot: 0, label: "test"}}, mechanisms: []uint{pkcs11EdDSA},
		private: pkcs11Key{class: 3, keyType: 0x40, sign: true, sensitive: true, nonExtractable: true, params: []byte{6, 3, 43, 101, 112}},
		public:  pkcs11Key{class: 2, keyType: 0x40, params: []byte{6, 3, 43, 101, 112}, point: priv.PubKey().Bytes()}, privateCount: 1, publicCount: 1}
}
func (f *fakePKCS11) Tokens() ([]pkcs11Token, error)  { return f.tokens, nil }
func (f *fakePKCS11) Mechanisms(uint) ([]uint, error) { return f.mechanisms, nil }
func (f *fakePKCS11) Open(uint) (uint, error)         { f.opens++; return uint(f.opens), nil }
func (f *fakePKCS11) Close(uint) error                { f.closes++; return nil }
func (f *fakePKCS11) Login(_ uint, pin string) error {
	f.logins++
	if pin != " 1234 " {
		return errors.New("PIN whitespace changed")
	}
	return f.loginErr
}
func (f *fakePKCS11) Find(_ uint, private bool, _ PKCS11Config) ([]uint, error) {
	n := f.publicCount
	if private {
		n = f.privateCount
	}
	return make([]uint, n), nil
}
func (f *fakePKCS11) Key(_ uint, _ uint, private bool) (pkcs11Key, error) {
	if private {
		return f.private, nil
	}
	return f.public, nil
}
func (f *fakePKCS11) Sign(_ uint, _ uint, msg []byte) ([]byte, error) {
	if f.active.Add(1) != 1 {
		f.overlap.Store(true)
	}
	defer f.active.Add(-1)
	time.Sleep(time.Microsecond)
	if f.signErr != nil {
		err := f.signErr
		f.signErr = nil
		return nil, err
	}
	if f.signFunc != nil {
		return f.signFunc(msg)
	}
	return f.priv.Sign(msg)
}
func pkcs11Fixture(t *testing.T) (PKCS11Config, *fakePKCS11) {
	t.Helper()
	dir := t.TempDir()
	pin := filepath.Join(dir, "pin")
	require.NoError(t, os.WriteFile(pin, []byte(" 1234 \r\n"), 0600))
	return PKCS11Config{Module: "fake.so", TokenLabel: "test", KeyLabel: "key", PINFile: pin, BindingFile: filepath.Join(dir, "binding")}, newFakePKCS11()
}
func openFakePKCS11(t *testing.T, cfg PKCS11Config, f *fakePKCS11) *PKCS11 {
	t.Helper()
	b, err := newPKCS11(cfg, f, func() error { return nil })
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, b.Close()) })
	return b
}
func TestPKCS11Config(t *testing.T) {
	cfg, _ := pkcs11Fixture(t)
	require.NoError(t, ValidatePKCS11Config(cfg))
	for _, field := range []string{"module", "pin_file", "binding_file", "token", "key", "id", "both tokens"} {
		t.Run(field, func(t *testing.T) {
			c := cfg
			switch field {
			case "module":
				c.Module = ""
			case "pin_file":
				c.PINFile = ""
			case "binding_file":
				c.BindingFile = ""
			case "token":
				c.TokenLabel = ""
			case "key":
				c.KeyLabel = ""
			case "id":
				c.KeyID = "zz"
			case "both tokens":
				c.Slot = new(uint)
			}
			require.Error(t, ValidatePKCS11Config(c))
		})
	}
	cfg.TokenLabel = ""
	cfg.Slot = new(uint)
	cfg.KeyLabel = ""
	cfg.KeyID = "00ff"
	require.NoError(t, ValidatePKCS11Config(cfg))
}
func TestPKCS11StrictKeyValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		params []byte
		valid  bool
	}{
		{"oid", []byte{6, 3, 43, 101, 112}, true}, {"name", append([]byte{19, 12}, []byte("edwards25519")...), true},
		{"ed448", []byte{6, 3, 43, 101, 113}, false}, {"x25519", []byte{6, 3, 43, 101, 110}, false},
		{"trailing", []byte{6, 3, 43, 101, 112, 0}, false}, {"empty", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, private := range []bool{true, false} {
				cfg, f := pkcs11Fixture(t)
				if private {
					f.private.params = tc.params
				} else {
					f.public.params = tc.params
				}
				b, err := newPKCS11(cfg, f, func() error { return nil })
				if tc.valid {
					require.NoError(t, err)
					require.NoError(t, b.Close())
				} else {
					require.ErrorContains(t, err, "Ed25519")
					require.Equal(t, 1, f.closes)
				}
			}
		})
	}
	for _, tc := range []string{"raw", "wrapped", "short", "long", "bad der"} {
		t.Run(tc, func(t *testing.T) {
			cfg, f := pkcs11Fixture(t)
			switch tc {
			case "wrapped":
				f.public.point = append([]byte{4, 32}, f.public.point...)
			case "short":
				f.public.point = f.public.point[:31]
			case "long":
				f.public.point = append(f.public.point, 0)
			case "bad der":
				f.public.point = append([]byte{4, 31}, f.public.point...)
			}
			b, err := newPKCS11(cfg, f, func() error { return nil })
			if tc == "raw" || tc == "wrapped" {
				require.NoError(t, err)
				pub, e := b.PubKey()
				require.NoError(t, e)
				require.Equal(t, f.priv.PubKey().Bytes(), pub.Bytes())
				require.NoError(t, b.Close())
			} else {
				require.ErrorContains(t, err, "public key")
			}
		})
	}
}
func TestPKCS11SelectionRejectsAmbiguityAndUnsupportedKeys(t *testing.T) {
	for _, tc := range []string{"missing private", "duplicate private", "missing public", "duplicate public", "wrong class", "wrong type", "cannot sign", "duplicate token", "missing token", "missing mechanism"} {
		t.Run(tc, func(t *testing.T) {
			cfg, f := pkcs11Fixture(t)
			switch tc {
			case "missing private":
				f.privateCount = 0
			case "duplicate private":
				f.privateCount = 2
			case "missing public":
				f.publicCount = 0
			case "duplicate public":
				f.publicCount = 2
			case "wrong class":
				f.private.class = 2
			case "wrong type":
				f.public.keyType = 3
			case "cannot sign":
				f.private.sign = false
			case "duplicate token":
				f.tokens = append(f.tokens, f.tokens[0])
			case "missing token":
				f.tokens = nil
			case "missing mechanism":
				f.mechanisms = nil
			}
			_, err := newPKCS11(cfg, f, func() error { return nil })
			require.Error(t, err)
		})
	}
}
func TestPKCS11SignRejectsInvalidSignatures(t *testing.T) {
	for _, tc := range []string{"short", "other key", "invalid"} {
		t.Run(tc, func(t *testing.T) {
			cfg, f := pkcs11Fixture(t)
			b := openFakePKCS11(t, cfg, f)
			f.signFunc = func(msg []byte) ([]byte, error) {
				switch tc {
				case "short":
					return []byte{1}, nil
				case "other key":
					return ed25519.GenPrivKey().Sign(msg)
				default:
					return make([]byte, 64), nil
				}
			}
			sig, err := b.Sign([]byte("message"))
			require.Error(t, err)
			require.Nil(t, sig)
		})
	}
}
func TestPKCS11RejectsExportableKeys(t *testing.T) {
	for _, attribute := range []string{"sensitive", "non-extractable"} {
		t.Run(attribute, func(t *testing.T) {
			cfg, f := pkcs11Fixture(t)
			if attribute == "sensitive" {
				f.private.sensitive = false
			} else {
				f.private.nonExtractable = false
			}
			be, err := newPKCS11(cfg, f, func() error { return nil })
			if be != nil {
				require.NoError(t, be.Close())
			}
			require.ErrorContains(t, err, "sensitive and non-extractable")
		})
	}
}

func TestPKCS11PreflightRejectsHedgedSignatures(t *testing.T) {
	cfg, f := pkcs11Fixture(t)
	b := openFakePKCS11(t, cfg, f)
	require.NoError(t, b.VerifyCanSign(t.Context()))
	f.signFunc = func(msg []byte) ([]byte, error) {
		return voi.PrivateKey(f.priv).Sign(rand.Reader, msg, &voi.Options{AddedRandomness: true})
	}
	require.ErrorContains(t, b.VerifyCanSign(t.Context()), "not deterministic")
}
func TestPKCS11Recovery(t *testing.T) {
	for _, code := range []uint{0xb0, 0xb3, 0x32, 0xe0, 0x101} {
		t.Run(pkcs11Error(code).Error(), func(t *testing.T) {
			cfg, f := pkcs11Fixture(t)
			b := openFakePKCS11(t, cfg, f)
			f.signErr = pkcs11Error(code)
			sig, err := b.Sign([]byte("message"))
			require.NoError(t, err)
			require.True(t, f.priv.PubKey().VerifySignature([]byte("message"), sig))
			require.Equal(t, 2, f.opens)
		})
	}
	t.Run("unrecoverable", func(t *testing.T) {
		cfg, f := pkcs11Fixture(t)
		b := openFakePKCS11(t, cfg, f)
		f.signErr = pkcs11Error(5)
		_, err := b.Sign([]byte("message"))
		require.Error(t, err)
		require.Equal(t, 1, f.opens)
		sig, err := b.Sign([]byte("message"))
		require.NoError(t, err)
		require.True(t, f.priv.PubKey().VerifySignature([]byte("message"), sig))
		require.Equal(t, 2, f.opens)
	})
	t.Run("replacement", func(t *testing.T) {
		cfg, f := pkcs11Fixture(t)
		b := openFakePKCS11(t, cfg, f)
		f.public.point = ed25519.GenPrivKey().PubKey().Bytes()
		f.signErr = pkcs11Error(0xb3)
		sig, err := b.Sign([]byte("message"))
		require.ErrorContains(t, err, "key changed")
		require.Nil(t, sig)
		require.ErrorIs(t, b.ClaimCluster(t.Context(), clusterA), ErrBindingCorrupt)
		_, err = b.ClusterBinding(t.Context())
		require.ErrorIs(t, err, ErrBindingUnclaimed)
	})
	t.Run("absent then returned", func(t *testing.T) {
		cfg, f := pkcs11Fixture(t)
		b := openFakePKCS11(t, cfg, f)
		tokens := f.tokens
		f.tokens = nil
		f.signErr = pkcs11Error(0xe0)
		_, err := b.Sign([]byte("message"))
		require.Error(t, err)
		f.tokens = tokens
		_, err = b.Sign([]byte("message"))
		require.NoError(t, err)
	})
	for _, code := range []uint{0xa0, 0xa4} {
		t.Run("PIN latch "+pkcs11Error(code).Error(), func(t *testing.T) {
			cfg, f := pkcs11Fixture(t)
			b := openFakePKCS11(t, cfg, f)
			f.signErr = pkcs11Error(0x101)
			f.loginErr = pkcs11Error(code)
			_, err := b.Sign([]byte("message"))
			require.ErrorIs(t, err, ErrPKCS11PINFailure)
			attempts := f.logins
			for range 3 {
				sig, e := b.Sign([]byte("message"))
				require.ErrorIs(t, e, ErrPKCS11PINFailure)
				require.Nil(t, sig)
			}
			require.ErrorIs(t, b.VerifyCanSign(t.Context()), ErrPKCS11PINFailure)
			require.ErrorIs(t, b.ClaimCluster(t.Context(), clusterA), ErrPKCS11PINFailure)
			require.Equal(t, attempts, f.logins)
		})
	}
}
func TestPKCS11SerializedSigningAndClose(t *testing.T) {
	cfg, f := pkcs11Fixture(t)
	b := openFakePKCS11(t, cfg, f)
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() { _, err := b.Sign([]byte("message")); require.NoError(t, err) })
	}
	wg.Wait()
	require.False(t, f.overlap.Load())
	require.NoError(t, b.Close())
	require.NoError(t, b.Close())
	_, err := b.Sign([]byte("message"))
	require.ErrorContains(t, err, "closed")
}
func TestPKCS11BindingChecksLiveKey(t *testing.T) {
	cfg, f := pkcs11Fixture(t)
	cfg.TokenLabel = ""
	cfg.Slot = new(uint)
	b := openFakePKCS11(t, cfg, f)
	require.Contains(t, BindingResource(b), "slot 0")
	require.NoError(t, b.ClaimCluster(t.Context(), clusterA))
	require.NoError(t, RequireClusterBinding(t.Context(), b, clusterA))
	require.ErrorIs(t, b.ClaimCluster(t.Context(), clusterB), ErrBindingMismatch)
	f.public.point = bytes.Repeat([]byte{1}, 32)
	require.ErrorIs(t, b.ClaimCluster(t.Context(), clusterA), ErrBindingCorrupt)
}

func TestPKCS11ClaimRecoveryPreservesPINFailure(t *testing.T) {
	cfg, f := pkcs11Fixture(t)
	b := openFakePKCS11(t, cfg, f)
	f.signErr = pkcs11Error(5)
	_, err := b.Sign([]byte("message"))
	require.Error(t, err)
	f.loginErr = pkcs11Error(0xa0)
	err = b.ClaimCluster(t.Context(), clusterA)
	require.True(t, pkcs11Code(err, 0xa0), "claim recovery must preserve the PIN cause: %v", err)
	require.ErrorIs(t, err, ErrPKCS11PINFailure)
	require.NotErrorIs(t, err, ErrBindingCorrupt)
	require.Equal(t, 2, f.logins)
	_, err = b.ClusterBinding(t.Context())
	require.ErrorIs(t, err, ErrBindingUnclaimed)
}

func TestPKCS11ConstructorLoginFailure(t *testing.T) {
	for _, code := range []uint{0xa0, 0xa4, 5} {
		t.Run(pkcs11Error(code).Error(), func(t *testing.T) {
			cfg, f := pkcs11Fixture(t)
			f.loginErr = pkcs11Error(code)
			releases := 0
			b, err := newPKCS11(cfg, f, func() error { releases++; return nil })
			require.Nil(t, b)
			require.True(t, pkcs11Code(err, code), "constructor must preserve the login cause: %v", err)
			require.Equal(t, code != 5, errors.Is(err, ErrPKCS11PINFailure))
			require.Equal(t, 1, f.logins)
			require.Equal(t, 1, f.closes)
			require.Equal(t, 1, releases)
		})
	}
}
