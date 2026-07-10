package signature

import (
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

type countingVerifier struct {
	calls atomic.Int64
	id    SignedIdentity
	err   error
}

func (c *countingVerifier) Verify(string) (SignedIdentity, error) {
	c.calls.Add(1)
	return c.id, c.err
}

// TestCachingVerifier_DedupesByExeAndMtime — repeated Verify of the same
// (exe, mtime) hits the cache after the first call, leaving the inner
// verifier untouched. This is the win we're after: 100 short HTTPS requests
// from the same script no longer fork codesign 100 times.
func TestCachingVerifier_DedupesByExeAndMtime(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "bin")
	if err := os.WriteFile(exe, []byte("hello"), 0o755); err != nil {
		t.Fatal(err)
	}

	inner := &countingVerifier{id: SignedIdentity{Valid: true, TeamID: "X"}}
	c := NewCachingVerifier(inner, 4)

	for i := 0; i < 5; i++ {
		id, err := c.Verify(exe)
		if err != nil {
			t.Fatal(err)
		}
		if id.TeamID != "X" {
			t.Errorf("got %+v", id)
		}
	}
	if got := inner.calls.Load(); got != 1 {
		t.Errorf("inner calls = %d, want 1 (cached)", got)
	}
}

// TestCachingVerifier_StatErrorBypassesCache — when os.Stat fails (no such
// file), the cache cannot key the entry; we fall through to the inner
// verifier so the real error reaches the caller.
func TestCachingVerifier_StatErrorBypassesCache(t *testing.T) {
	inner := &countingVerifier{err: errors.New("boom")}
	c := NewCachingVerifier(inner, 4)
	_, err := c.Verify("/nonexistent/path")
	if err == nil {
		t.Errorf("expected inner error")
	}
}
