package clusterid

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewReturnsCanonicalRandomUUID(t *testing.T) {
	first, err := New()
	require.NoError(t, err)
	require.NoError(t, Validate(first))

	second, err := New()
	require.NoError(t, err)
	require.NoError(t, Validate(second))
	require.NotEqual(t, first, second)
}

func TestValidateRejectsNonCanonicalIDs(t *testing.T) {
	for _, id := range []string{
		"",
		"3B12F1DF-5232-4804-897E-917BF397618A",
		"3b12f1df52324804897e917bf397618a",
		"3b12f1df-5232-4804-897e-917bf397618",
		"3b12f1df-5232-4804-897e-917bf397618z",
		"00000000-0000-0000-0000-000000000000",
		"3b12f1df-5232-1804-897e-917bf397618a",
		"3b12f1df-5232-4804-797e-917bf397618a",
	} {
		t.Run(id, func(t *testing.T) {
			require.Error(t, Validate(id))
		})
	}
}

func TestValidateAcceptsCanonicalID(t *testing.T) {
	require.NoError(t, Validate("3b12f1df-5232-4804-897e-917bf397618a"))
}
