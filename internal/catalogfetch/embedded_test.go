package catalogfetch

import (
	"crypto/ed25519"
	"os"
	"testing"

	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/catalogsig"
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

func TestCommittedBaselineSignature_VerifiesWithMaintainerKey(t *testing.T) {
	pub, err := MaintainerKey()
	if err != nil {
		t.Fatalf("MaintainerKey: %v", err)
	}
	data, err := os.ReadFile("../../catalog-baseline.toml")
	if err != nil {
		t.Fatalf("read committed catalog: %v", err)
	}
	sig, err := os.ReadFile("../../catalog-baseline.toml.sig")
	if err != nil {
		t.Fatalf("read committed signature: %v", err)
	}
	if err := catalogsig.Verify(data, sig, pub); err != nil {
		t.Fatalf("committed catalog signature does not verify: %v", err)
	}
	if _, err := catalog.Load(data); err != nil {
		t.Fatalf("committed catalog does not parse: %v", err)
	}
}
