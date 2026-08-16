package daemon

import (
	"container/list"
	"os"
	"path/filepath"
	"testing"
)

func TestExeSHA256CachesByPathMtimeAndSize(t *testing.T) {
	resetExeHashCacheForTest(t)
	path := filepath.Join(t.TempDir(), "tool")
	if err := os.WriteFile(path, []byte("v1"), 0o755); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	calls := 0
	hashExecutable = func(string) string {
		calls++
		return "hash-v1"
	}
	if got := exeSHA256(path); got != "hash-v1" {
		t.Fatalf("first hash = %q, want hash-v1", got)
	}
	if got := exeSHA256(path); got != "hash-v1" {
		t.Fatalf("cached hash = %q, want hash-v1", got)
	}
	if calls != 1 {
		t.Fatalf("hashExecutable calls = %d, want 1", calls)
	}

	hashExecutable = func(string) string {
		calls++
		return "hash-v2"
	}
	if err := os.WriteFile(path, []byte("v2 with new size"), 0o755); err != nil {
		t.Fatalf("rewrite fixture: %v", err)
	}
	if got := exeSHA256(path); got != "hash-v2" {
		t.Fatalf("hash after rewrite = %q, want hash-v2", got)
	}
	if calls != 2 {
		t.Fatalf("hashExecutable calls after rewrite = %d, want 2", calls)
	}
}

func resetExeHashCacheForTest(t *testing.T) {
	t.Helper()
	exeHashMu.Lock()
	exeHashLRU.Init()
	exeHashIndex = map[string]*list.Element{}
	hashExecutable = hashExecutableFile
	exeHashMu.Unlock()
	t.Cleanup(func() {
		exeHashMu.Lock()
		exeHashLRU.Init()
		exeHashIndex = map[string]*list.Element{}
		hashExecutable = hashExecutableFile
		exeHashMu.Unlock()
	})
}
