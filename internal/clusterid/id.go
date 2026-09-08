// Package clusterid owns the persistent identity format shared by Raft and key backends.
package clusterid

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
)

// New returns a random RFC 4122 version 4 UUID in canonical lowercase form.
func New() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate cluster ID: %w", err)
	}
	raw[6] = raw[6]&0x0f | 0x40
	raw[8] = raw[8]&0x3f | 0x80

	var encoded [36]byte
	hex.Encode(encoded[0:8], raw[0:4])
	encoded[8] = '-'
	hex.Encode(encoded[9:13], raw[4:6])
	encoded[13] = '-'
	hex.Encode(encoded[14:18], raw[6:8])
	encoded[18] = '-'
	hex.Encode(encoded[19:23], raw[8:10])
	encoded[23] = '-'
	hex.Encode(encoded[24:36], raw[10:16])
	return string(encoded[:]), nil
}

// Validate requires the canonical lowercase 8-4-4-4-12 UUID representation.
func Validate(id string) error {
	if len(id) != 36 {
		return fmt.Errorf("cluster ID must be a canonical lowercase UUID")
	}
	for i, b := range []byte(id) {
		switch i {
		case 8, 13, 18, 23:
			if b != '-' {
				return fmt.Errorf("cluster ID must be a canonical lowercase UUID")
			}
		default:
			if !((b >= '0' && b <= '9') || (b >= 'a' && b <= 'f')) {
				return fmt.Errorf("cluster ID must be a canonical lowercase UUID")
			}
		}
	}
	if id[14] != '4' || !strings.ContainsRune("89ab", rune(id[19])) {
		return fmt.Errorf("cluster ID must be a canonical RFC 4122 version 4 UUID")
	}
	return nil
}
