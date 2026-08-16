//go:build darwin

package nebridge

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/byliu-labs/egress-guard/internal/signature"
)

func TestSystemResolver_OwnToken(t *testing.T) {
	token, err := currentProcessAuditToken()
	if err != nil {
		t.Fatalf("currentProcessAuditToken: %v", err)
	}

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

func TestSystemResolver_TamperedPIDVersionFailsClosed(t *testing.T) {
	token, err := currentProcessAuditToken()
	if err != nil {
		t.Fatalf("currentProcessAuditToken: %v", err)
	}
	pidVersion := binary.NativeEndian.Uint32(token[7*4:])
	binary.NativeEndian.PutUint32(token[7*4:], pidVersion+1)

	_, _, err = NewSystemResolver(signature.NewStub()).Resolve(token)
	if err == nil || !strings.Contains(err.Error(), "Security.framework rejected audit token") {
		t.Fatalf("Resolve error = %v, want Security.framework audit-token rejection", err)
	}
}

func TestNewSystemResolver_NilVerifierFailsClosedOrVerifies(t *testing.T) {
	token, err := currentProcessAuditToken()
	if err != nil {
		t.Fatalf("currentProcessAuditToken: %v", err)
	}

	_, _, err = NewSystemResolver(nil).Resolve(token)
	if err != nil && !strings.Contains(err.Error(), "nebridge: verify") {
		t.Fatalf("Resolve with default verifier error = %v, want signature verification result", err)
	}
}
