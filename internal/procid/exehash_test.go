package procid

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestExeHasher_HashesAndResolvesSymlink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real-tool")
	if err := os.WriteFile(real, []byte("binary contents"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "tool")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}

	h := NewExeHasher()
	gotPath, gotSum, err := h.Hash(link)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	wantPath, err := filepath.EvalSymlinks(real)
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != wantPath {
		t.Errorf("realpath = %q, want %q", gotPath, wantPath)
	}
	want := sha256.Sum256([]byte("binary contents"))
	if gotSum != hex.EncodeToString(want[:]) {
		t.Errorf("sha256 = %q, want %q", gotSum, hex.EncodeToString(want[:]))
	}
}

func TestExeHasher_RehashesWhenFileChanges(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "tool")
	if err := os.WriteFile(p, []byte("v1"), 0o755); err != nil {
		t.Fatal(err)
	}
	h := NewExeHasher()
	_, first, err := h.Hash(p)
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(10 * time.Millisecond)
	if err := os.WriteFile(p, []byte("v2-different-length"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, second, err := h.Hash(p)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("cache returned a stale hash after the binary changed")
	}
}

func TestExeHasher_RehashesWhenSameInodeSizeAndMtimeChange(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "tool")
	firstContent := []byte("LEGITIMATE-BINARY-CONTENT")
	if err := os.WriteFile(p, firstContent, 0o755); err != nil {
		t.Fatal(err)
	}
	h := NewExeHasher()
	_, first, err := h.Hash(p)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	mtime := fi.ModTime()

	time.Sleep(20 * time.Millisecond)
	f, err := os.OpenFile(p, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte("MALICIOUS!!BINARY!!CONTEN"), 0); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(p, mtime, mtime); err != nil {
		t.Fatal(err)
	}

	_, second, err := h.Hash(p)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("cache returned a stale hash after an in-place same-size rewrite with restored mtime")
	}
}

func TestExeHasher_RefusesOversizeFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "huge")
	if err := os.WriteFile(p, make([]byte, 32), 0o755); err != nil {
		t.Fatal(err)
	}
	h := &ExeHasher{maxBytes: 16, cache: map[hashKey]string{}}
	if _, _, err := h.Hash(p); err == nil {
		t.Fatal("expected refusal for a file over maxBytes")
	}
}
