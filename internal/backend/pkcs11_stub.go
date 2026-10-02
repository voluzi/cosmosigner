//go:build !pkcs11 || !cgo

package backend

import "errors"

const PKCS11Supported = false

func NewPKCS11(PKCS11Config) (*PKCS11, error) {
	return nil, errors.New("this binary was built without PKCS#11 support; rebuild with CGO_ENABLED=1 and -tags pkcs11")
}
