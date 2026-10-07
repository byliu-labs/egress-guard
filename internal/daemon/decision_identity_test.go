package daemon

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/byliu-labs/egress-guard/internal/procid"
	"github.com/byliu-labs/egress-guard/internal/signature"
)

func TestIdentityFor_PopulatesPathAndHash(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "mytool")
	if err := os.WriteFile(exe, []byte("tool bytes"), 0o755); err != nil {
		t.Fatal(err)
	}
	wantPath, err := filepath.EvalSymlinks(exe)
	if err != nil {
		t.Fatal(err)
	}
	d := newDaemonForBaselineTest()
	d.hasher = procid.NewExeHasher()

	id := d.identityFor(procid.ProcInfo{Exe: exe, Comm: "mytool"}, signature.SignedIdentity{})

	if id.ExeBasename != "mytool" {
		t.Errorf("ExeBasename = %q, want mytool", id.ExeBasename)
	}
	if id.ExePath != wantPath {
		t.Errorf("ExePath = %q, want %q", id.ExePath, wantPath)
	}
	want := sha256.Sum256([]byte("tool bytes"))
	if id.ExeSHA256 != hex.EncodeToString(want[:]) {
		t.Errorf("ExeSHA256 = %q, want %q", id.ExeSHA256, hex.EncodeToString(want[:]))
	}
}

func TestIdentityFor_MissingBinaryLeavesHashEmpty(t *testing.T) {
	d := newDaemonForBaselineTest()
	d.hasher = procid.NewExeHasher()
	id := d.identityFor(procid.ProcInfo{Exe: "/nonexistent/tool", Comm: "tool"}, signature.SignedIdentity{})
	if id.ExeSHA256 != "" {
		t.Errorf("ExeSHA256 = %q, want empty on hash failure", id.ExeSHA256)
	}
	if id.ExePath != "" {
		t.Errorf("ExePath = %q, want empty on hash failure", id.ExePath)
	}
	if id.ExeBasename != "tool" {
		t.Errorf("ExeBasename = %q, want tool", id.ExeBasename)
	}
}
