package catalogfetch

import (
	"crypto/ed25519"
	"testing"
)

func TestMaintainerKey_IsAWellFormedEd25519PublicKey(t *testing.T) {
	pub, err := MaintainerKey()
	if err != nil {
		t.Fatalf("MaintainerKey: %v", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("embedded key is %d bytes, want %d", len(pub), ed25519.PublicKeySize)
	}
}
