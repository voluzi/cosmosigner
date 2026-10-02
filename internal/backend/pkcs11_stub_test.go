//go:build !pkcs11 || !cgo

package backend

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPKCS11UnsupportedBuild(t *testing.T) {
	cfg, _ := pkcs11Fixture(t)
	_, err := New(Config{Type: TypePKCS11, PKCS11: cfg})
	require.ErrorContains(t, err, "built without PKCS#11 support")
}
