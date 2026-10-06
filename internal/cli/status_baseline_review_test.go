//go:build darwin

package cli

import (
	"os"
	"github.com/byliu-labs/egress-guard/internal/rejected"
	"path/filepath"
	"testing"
	"time"
)

func TestBaselineReviewCountExcludesRejectedPair(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "config"))
	logPath, err := BlockLogPath()
	if err != nil {
		t.Fatal(err)
	}
	writeLog(t, logPath, twoDayPair("/bin/curl", "evil.example"))
	store, err := rejected.Open(filepath.Join(dir, "config", "egress-guard", "rejected-pairs.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	// The fixture is historical; the count helper takes an explicit reference time.
	now := time.Date(2026, 7, 4, 0, 0, 0, 0, time.UTC)
	if n := baselineReviewCount(store, now); n != 1 {
		t.Fatalf("count before rejection=%d", n)
	}
	cachePath,err:=baselineCachePath();if err!=nil {t.Fatal(err)}
	if _,err:=os.Stat(cachePath);!os.IsNotExist(err) {t.Fatalf("status probe wrote baseline cache: %v",err)}
	if err := store.Reject(rejected.Key{ExeBasename: "curl", Host: "evil.example"}, ""); err != nil {
		t.Fatal(err)
	}
	if n := baselineReviewCount(store, now); n != 0 {
		t.Fatalf("count after rejection=%d", n)
	}
}
