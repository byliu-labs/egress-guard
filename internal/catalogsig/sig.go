// Package catalogsig signs and verifies detached Ed25519 signatures over
// compiled catalog bytes.
package catalogsig

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
)

// GenerateKey returns a fresh Ed25519 keypair for catalog signing.
func GenerateKey() ([]byte, []byte, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("catalogsig: generate key: %w", err)
	}
	return []byte(pub), []byte(priv), nil
}

// Sign returns a detached Ed25519 signature of data under priv.
func Sign(data, priv []byte) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("catalogsig: bad private key size %d (want %d)", len(priv), ed25519.PrivateKeySize)
	}
	return ed25519.Sign(ed25519.PrivateKey(priv), data), nil
}

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
