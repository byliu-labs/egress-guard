package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/drift"
)

// Bumping the schema makes every installed machine's cache stale on upgrade.
// That must trigger a rebuild, never a daemon that will not start — egress
// protection cannot depend on a cache file being current.
func TestLoadStartupBaseline_SurvivesAStaleCache(t *testing.T) {
	dir := t.TempDir()
	cache := filepath.Join(dir, "baseline.json")
	if err := os.WriteFile(cache, []byte(`{"schema_version":3}`), 0o600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "decisions.log")
	if err := os.WriteFile(logPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	b := loadStartupBaseline(logPath, cache, &catalog.Catalog{}, stdLogger{})
	if b == nil {
		t.Fatal("a stale cache must produce a rebuilt baseline, not nil")
	}
	loaded, err := drift.LoadBaseline(cache, &catalog.Catalog{})
	if err != nil {
		t.Fatalf("rebuilt cache must load with the current persistence contract: %v", err)
	}
	if loaded == nil {
		t.Fatal("rebuilt cache loaded as nil baseline")
	}
}
