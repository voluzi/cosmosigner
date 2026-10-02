//go:build pkcs11 && cgo

package backend

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	p11 "github.com/miekg/pkcs11"
)

const PKCS11Supported = true

type nativePKCS11 struct {
	ctx  *p11.Ctx
	path string
}
type pkcs11PINResource struct {
	manufacturer, model, serial string
}

var pkcs11PINFailures = struct {
	sync.Mutex
	failures map[pkcs11PINResource]error
}{failures: make(map[pkcs11PINResource]error)}

type pkcs11ModuleEntry struct {
	native *nativePKCS11
	refs   int
	owned  bool
}

var pkcs11Modules = struct {
	sync.Mutex
	entries map[string]*pkcs11ModuleEntry
	files   map[string]os.FileInfo
}{entries: make(map[string]*pkcs11ModuleEntry), files: make(map[string]os.FileInfo)}

func NewPKCS11(cfg PKCS11Config) (*PKCS11, error) {
	if err := ValidatePKCS11Config(cfg); err != nil {
		return nil, err
	}
	module, release, err := acquirePKCS11Module(cfg.Module)
	if err != nil {
		return nil, err
	}
	return newPKCS11(cfg, module, release)
}
func acquirePKCS11Module(path string) (*nativePKCS11, func() error, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve pkcs11 module: %w", err)
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve pkcs11 module: %w", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, nil, fmt.Errorf("inspect pkcs11 module: %w", err)
	}
	loadPath := path
	pkcs11Modules.Lock()
	defer pkcs11Modules.Unlock()
	// dlopen coalesces hard links too; retained identities must still name the same file.
	for knownPath, knownInfo := range pkcs11Modules.files {
		if os.SameFile(info, knownInfo) {
			// Unloaded files can disappear and their inodes can be reused by other modules.
			if pkcs11Modules.entries[knownPath] == nil {
				currentInfo, statErr := os.Stat(knownPath)
				if errors.Is(statErr, os.ErrNotExist) || (statErr == nil && !os.SameFile(currentInfo, knownInfo)) {
					delete(pkcs11Modules.files, knownPath)
					continue
				}
				if statErr != nil {
					return nil, nil, fmt.Errorf("inspect cached pkcs11 module %q: %w", knownPath, statErr)
				}
			}
			path = knownPath
			break
		}
	}
	entry := pkcs11Modules.entries[path]
	if entry == nil {
		ctx := p11.New(loadPath)
		if ctx == nil {
			return nil, nil, fmt.Errorf("load pkcs11 module %q", path)
		}
		err := ctx.Initialize()
		owned := err == nil
		if err != nil && err != p11.Error(p11.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
			ctx.Destroy()
			return nil, nil, fmt.Errorf("initialize pkcs11 module: %w", nativePKCS11Error(err))
		}
		entry = &pkcs11ModuleEntry{native: &nativePKCS11{ctx: ctx, path: path}, owned: owned}
		pkcs11Modules.entries[path] = entry
		pkcs11Modules.files[path] = info
	}
	entry.refs++
	// Finalize only our own initialization, after every backend has closed its session.
	// Recovery never finalizes, and an externally initialized module remains untouched.
	release := func() error {
		pkcs11Modules.Lock()
		defer pkcs11Modules.Unlock()
		entry.refs--
		if entry.refs != 0 {
			return nil
		}
		var err error
		if entry.owned {
			err = entry.native.ctx.Finalize()
		}
		entry.native.ctx.Destroy()
		delete(pkcs11Modules.entries, path)
		return nativePKCS11Error(err)
	}
	return entry.native, release, nil
}
func nativePKCS11Error(err error) error {
	if err == nil {
		return nil
	}
	var e p11.Error
	if errors.As(err, &e) {
		return pkcs11Error(e)
	}
	return err
}
func (n *nativePKCS11) Tokens() ([]pkcs11Token, error) {
	slots, err := n.ctx.GetSlotList(true)
	if err != nil {
		return nil, nativePKCS11Error(err)
	}
	tokens := make([]pkcs11Token, 0, len(slots))
	for _, slot := range slots {
		info, err := n.ctx.GetTokenInfo(slot)
		if err != nil {
			if err == p11.Error(p11.CKR_TOKEN_NOT_PRESENT) {
				continue
			}
			return nil, nativePKCS11Error(err)
		}
		tokens = append(tokens, pkcs11Token{slot: slot, label: info.Label})
	}
	return tokens, nil
}
func (n *nativePKCS11) Mechanisms(slot uint) ([]uint, error) {
	mechanisms, err := n.ctx.GetMechanismList(slot)
	if err != nil {
		return nil, nativePKCS11Error(err)
	}
	values := make([]uint, len(mechanisms))
	for i, m := range mechanisms {
		values[i] = m.Mechanism
	}
	return values, nil
}
func (n *nativePKCS11) Open(slot uint) (uint, error) {
	sh, err := n.ctx.OpenSession(slot, p11.CKF_SERIAL_SESSION)
	return uint(sh), nativePKCS11Error(err)
}
func (n *nativePKCS11) Close(sh uint) error {
	err := n.ctx.CloseSession(p11.SessionHandle(sh))
	if err == p11.Error(p11.CKR_SESSION_HANDLE_INVALID) || err == p11.Error(p11.CKR_SESSION_CLOSED) {
		return nil
	}
	return nativePKCS11Error(err)
}
func (n *nativePKCS11) Login(sh uint, pin string) error {
	info, err := n.ctx.GetSessionInfo(p11.SessionHandle(sh))
	if err != nil {
		return nativePKCS11Error(err)
	}
	token, err := n.ctx.GetTokenInfo(info.SlotID)
	if err != nil {
		return nativePKCS11Error(err)
	}
	if strings.TrimSpace(token.SerialNumber) == "" {
		return errors.New("pkcs11 token must report a serial number for PIN retry protection")
	}
	resource := pkcs11PINResource{manufacturer: token.ManufacturerID, model: token.Model, serial: token.SerialNumber}
	// Retain failures across backend close/reopen, and serialize concurrent login attempts.
	pkcs11PINFailures.Lock()
	defer pkcs11PINFailures.Unlock()
	if failure := pkcs11PINFailures.failures[resource]; failure != nil {
		return failure
	}
	err = nativePKCS11Error(n.ctx.Login(p11.SessionHandle(sh), p11.CKU_USER, pin))
	if pkcs11Code(err, 0xa0, 0xa4) {
		err = fmt.Errorf("pkcs11 PIN failure latched for this process: %w", err)
		pkcs11PINFailures.failures[resource] = err
	}
	return err
}
func (n *nativePKCS11) Find(sh uint, private bool, cfg PKCS11Config) (objects []uint, resultErr error) {
	class := uint(p11.CKO_PUBLIC_KEY)
	if private {
		class = p11.CKO_PRIVATE_KEY
	}
	template := []*p11.Attribute{p11.NewAttribute(p11.CKA_CLASS, class), p11.NewAttribute(p11.CKA_KEY_TYPE, uint(pkcs11Edwards))}
	if private {
		template = append(template, p11.NewAttribute(p11.CKA_SIGN, true))
	}
	if cfg.KeyLabel != "" {
		template = append(template, p11.NewAttribute(p11.CKA_LABEL, cfg.KeyLabel))
	}
	if cfg.KeyID != "" {
		id, err := hex.DecodeString(cfg.KeyID)
		if err != nil {
			return nil, err
		}
		template = append(template, p11.NewAttribute(p11.CKA_ID, id))
	}
	session := p11.SessionHandle(sh)
	if err := n.ctx.FindObjectsInit(session, template); err != nil {
		return nil, nativePKCS11Error(err)
	}
	defer func() { resultErr = errors.Join(resultErr, nativePKCS11Error(n.ctx.FindObjectsFinal(session))) }()
	// Two matches are sufficient to reject ambiguity. Ignore the SDK's deprecated boolean.
	for len(objects) < 2 {
		found, _, err := n.ctx.FindObjects(session, 2-len(objects))
		if err != nil {
			return nil, nativePKCS11Error(err)
		}
		if len(found) == 0 {
			break
		}
		for _, obj := range found {
			objects = append(objects, uint(obj))
		}
	}
	return objects, nil
}
func (n *nativePKCS11) Key(sh, obj uint, private bool) (pkcs11Key, error) {
	types := []uint{p11.CKA_CLASS, p11.CKA_KEY_TYPE, p11.CKA_EC_PARAMS}
	if private {
		types = append(types, p11.CKA_SIGN, p11.CKA_SENSITIVE, p11.CKA_EXTRACTABLE)
	} else {
		types = append(types, p11.CKA_EC_POINT)
	}
	request := make([]*p11.Attribute, len(types))
	for i, typ := range types {
		request[i] = p11.NewAttribute(typ, nil)
	}
	attributes, err := n.ctx.GetAttributeValue(p11.SessionHandle(sh), p11.ObjectHandle(obj), request)
	if err != nil {
		return pkcs11Key{}, nativePKCS11Error(err)
	}
	var key pkcs11Key
	for _, a := range attributes {
		switch a.Type {
		case p11.CKA_CLASS:
			class := uint(p11.CKO_PUBLIC_KEY)
			if private {
				class = p11.CKO_PRIVATE_KEY
			}
			if bytes.Equal(a.Value, p11.NewAttribute(a.Type, class).Value) {
				key.class = class
			}
		case p11.CKA_KEY_TYPE:
			if bytes.Equal(a.Value, p11.NewAttribute(a.Type, uint(pkcs11Edwards)).Value) {
				key.keyType = pkcs11Edwards
			}
		case p11.CKA_SIGN:
			key.sign = bytes.Equal(a.Value, p11.NewAttribute(a.Type, true).Value)
		case p11.CKA_SENSITIVE:
			key.sensitive = bytes.Equal(a.Value, p11.NewAttribute(a.Type, true).Value)
		case p11.CKA_EXTRACTABLE:
			key.nonExtractable = bytes.Equal(a.Value, p11.NewAttribute(a.Type, false).Value)
		case p11.CKA_EC_PARAMS:
			key.params = a.Value
		case p11.CKA_EC_POINT:
			key.point = a.Value
		}
	}
	return key, nil
}
func (n *nativePKCS11) Sign(sh, obj uint, msg []byte) ([]byte, error) {
	session := p11.SessionHandle(sh)
	if err := n.ctx.SignInit(session, []*p11.Mechanism{p11.NewMechanism(pkcs11EdDSA, nil)}, p11.ObjectHandle(obj)); err != nil {
		return nil, nativePKCS11Error(err)
	}
	sig, err := n.ctx.Sign(session, msg)
	return sig, nativePKCS11Error(err)
}
