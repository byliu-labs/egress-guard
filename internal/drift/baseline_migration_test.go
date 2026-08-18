package drift

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/byliu-labs/egress-guard/internal/catalog"
)

func TestBaselineSchemaVersion_WasBumped(t *testing.T) {
	if baselineSchemaVersion < 5 {
		t.Errorf("baselineSchemaVersion = %d; adding cloud pair metadata must bump it", baselineSchemaVersion)
	}
}

// A snapshot from the previous point space must not load as if it were
// current — it would score live connections against the wrong geometry.
func TestLoadBaseline_PreviousPointSpaceDoesNotLoad(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "baseline.json")
	old := `{"schema_version":3,"built_through":"2026-08-01T00:00:00Z",` +
		`"identities":["a"],"hosts":["b"],"pairs":["a b"]}`
	if err := os.WriteFile(p, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := LoadBaseline(p, &catalog.Catalog{})
	if err == nil && b != nil {
		t.Fatal("a version-3 snapshot must not load into a version-5 point space")
	}
}

func TestLoadBaseline_PreviousCloudMetadataDoesNotLoad(t *testing.T) {
	p := filepath.Join(t.TempDir(), "baseline.json")
	old := `{"schema_version":4,"built_through":"2026-08-01T00:00:00Z",` +
		`"identities":["a"],"hosts":["b"],"pairs":["a b"],"cloud_points":{}}`
	if err := os.WriteFile(p, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := LoadBaseline(p, &catalog.Catalog{})
	if err == nil && b != nil {
		t.Fatal("a version-4 snapshot lacks cloud pair metadata and must not load")
	}
}
