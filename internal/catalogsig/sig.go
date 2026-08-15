// Package catalogsig verifies detached Ed25519 signatures over compiled
// catalog bytes.
package catalogsig

import (
	"crypto/ed25519"
	"fmt"
)

// Verify checks that sig is a valid Ed25519 signature of data under pub.
func Verify(data, sig, pub []byte) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("catalogsig: bad public key size %d (want %d)", len(pub), ed25519.PublicKeySize)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), data, sig) {
		return fmt.Errorf("catalogsig: signature verification failed")
	}
	return nil
}
