package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/byliu-labs/egress-guard/internal/catalog"
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
	data, err := os.ReadFile(cache)
	if err != nil {
		t.Fatal(err)
	}
	var snapshot struct {
		SchemaVersion int `json:"schema_version"`
	}
	if err := json.Unmarshal(data, &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.SchemaVersion != 4 {
		t.Fatalf("cache schema version = %d, want rebuilt version 4", snapshot.SchemaVersion)
	}
}
