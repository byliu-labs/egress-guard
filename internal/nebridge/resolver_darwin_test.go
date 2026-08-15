//go:build darwin

package nebridge

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/byliu-labs/egress-guard/internal/signature"
)

func TestSystemResolver_OwnToken(t *testing.T) {
	var token [32]byte
	// audit_token_t is eight native-endian uint32_t values; pid is val[5].
	binary.NativeEndian.PutUint32(token[5*4:], uint32(os.Getpid()))

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		t.Fatalf("EvalSymlinks(%q): %v", exe, err)
	}
	verifier := signature.NewStub()
	verifier.ByExe[exe] = signature.SignedIdentity{Valid: true}

	resolver := NewSystemResolver(verifier)
	pi, id, err := resolver.Resolve(token)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if pi.PID != os.Getpid() {
		t.Errorf("PID = %d, want %d", pi.PID, os.Getpid())
	}
	if pi.Exe != exe {
		t.Errorf("Exe = %q, want %q", pi.Exe, exe)
	}
	if pi.Comm != filepath.Base(exe) {
		t.Errorf("Comm = %q, want %q", pi.Comm, filepath.Base(exe))
	}
	if !id.Valid {
		t.Errorf("signed identity = %+v, want valid test identity", id)
	}
}
