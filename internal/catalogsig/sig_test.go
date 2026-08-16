package catalogsig

import (
	"crypto/ed25519"
	"testing"
)

func TestVerify_AcceptsGoodSignature(t *testing.T) {
	pub, priv, _ := GenerateKey()
	data := []byte("catalog bytes")
	sig, err := Sign(data, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := Verify(data, sig, pub); err != nil {
		t.Fatalf("Verify rejected a valid signature: %v", err)
	}
}

func TestSign_RejectsWrongPrivateKeySize(t *testing.T) {
	if _, err := Sign([]byte("x"), []byte("short")); err == nil {
		t.Fatal("Sign accepted a malformed private key")
	}
}

func TestVerify_RejectsTamperedData(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	sig := ed25519.Sign(priv, []byte("original"))
	if err := Verify([]byte("tampered"), sig, pub); err == nil {
		t.Fatal("Verify accepted a signature over different data")
	}
}

func TestVerify_RejectsWrongKeySize(t *testing.T) {
	if err := Verify([]byte("x"), []byte("y"), []byte("short")); err == nil {
		t.Fatal("Verify accepted a malformed public key")
	}
}
