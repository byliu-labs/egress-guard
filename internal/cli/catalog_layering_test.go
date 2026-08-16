package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/byliu-labs/egress-guard/internal/catalog"
)

func writeCatalogFile(t *testing.T, path string, entries ...catalog.Entry) {
	t.Helper()
	c := &catalog.Catalog{}
	for _, e := range entries {
		if err := c.Add(e); err != nil {
			t.Fatalf("Add(%+v): %v", e, err)
		}
	}
	b, err := c.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func allowEntry(layer, exe, host string) catalog.Entry {
	return catalog.Entry{
		SchemaVersion:        catalog.CurrentSchemaVersion,
		Identity:             catalog.Identity{ExeBasename: exe, TeamID: "TESTTEAM"},
		ExpectedDestinations: []catalog.Destination{{Host: host, Why: "test allow"}},
		Explanation:          "test allow entry",
		Evidence:             "test evidence",
		Confidence:           catalog.ConfidenceMedium,
		Layer:                layer,
	}
}

func neverEntry(layer, exe, host string) catalog.Entry {
	return catalog.Entry{
		SchemaVersion: catalog.CurrentSchemaVersion,
		Identity:      catalog.Identity{ExeBasename: exe, TeamID: "TESTTEAM"},
		Never:         []string{host},
		Explanation:   "test deny entry",
		Evidence:      "test evidence",
		Confidence:    catalog.ConfidenceMedium,
		Layer:         layer,
	}
}

func TestLoadLayeredCatalog_BaselineAllowIsConsulted(t *testing.T) {
	dir := t.TempDir()
	basePath := filepath.Join(dir, "catalog-baseline.toml")
	userPath := filepath.Join(dir, "catalog-user.toml") // intentionally absent
	writeCatalogFile(t, basePath, allowEntry("baseline", "updater", "updates.example.com"))

	live, err := loadLayeredCatalog(basePath, userPath)
	if err != nil {
		t.Fatalf("loadLayeredCatalog: %v", err)
	}
	got := live.Lookup(catalog.Identity{ExeBasename: "updater", TeamID: "TESTTEAM"}, "updates.example.com")
	if !got.Found || got.NeverHit {
		t.Fatalf("baseline allow not consulted: Found=%v NeverHit=%v", got.Found, got.NeverHit)
	}
}

func TestLoadLayeredCatalog_DenyInAnyLayerWinsOverBaselineAllow(t *testing.T) {
	dir := t.TempDir()
	basePath := filepath.Join(dir, "catalog-baseline.toml")
	userPath := filepath.Join(dir, "catalog-user.toml")
	// Baseline says allow; user later denies the same identity+host.
	writeCatalogFile(t, basePath, allowEntry("baseline", "updater", "updates.example.com"))
	writeCatalogFile(t, userPath, neverEntry("user", "updater", "updates.example.com"))

	live, err := loadLayeredCatalog(basePath, userPath)
	if err != nil {
		t.Fatalf("loadLayeredCatalog: %v", err)
	}
	got := live.Lookup(catalog.Identity{ExeBasename: "updater", TeamID: "TESTTEAM"}, "updates.example.com")
	if !got.NeverHit {
		t.Fatalf("deny must win over a baseline allow: Found=%v NeverHit=%v", got.Found, got.NeverHit)
	}
}

func TestLoadLayeredCatalog_DenyInBaselineWinsOverUserAllow(t *testing.T) {
	// Symmetric to the case above: the deny sits in the baseline (first in the
	// merged entries) and the allow in the user layer (second). Deny must still
	// win, proving precedence is order-independent, not an artifact of the deny
	// happening to be scanned last.
	dir := t.TempDir()
	basePath := filepath.Join(dir, "catalog-baseline.toml")
	userPath := filepath.Join(dir, "catalog-user.toml")
	writeCatalogFile(t, basePath, neverEntry("baseline", "updater", "updates.example.com"))
	writeCatalogFile(t, userPath, allowEntry("user", "updater", "updates.example.com"))

	live, err := loadLayeredCatalog(basePath, userPath)
	if err != nil {
		t.Fatalf("loadLayeredCatalog: %v", err)
	}
	got := live.Lookup(catalog.Identity{ExeBasename: "updater", TeamID: "TESTTEAM"}, "updates.example.com")
	if !got.NeverHit {
		t.Fatalf("deny in baseline must win over a user allow: Found=%v NeverHit=%v", got.Found, got.NeverHit)
	}
}

func TestLoadLayeredCatalog_MissingBaselineIsEmptyLayer(t *testing.T) {
	dir := t.TempDir()
	basePath := filepath.Join(dir, "catalog-baseline.toml") // intentionally absent
	userPath := filepath.Join(dir, "catalog-user.toml")
	writeCatalogFile(t, userPath, allowEntry("user", "curl", "api.example.com"))

	live, err := loadLayeredCatalog(basePath, userPath)
	if err != nil {
		t.Fatalf("loadLayeredCatalog with absent baseline must not error: %v", err)
	}
	if got := live.Lookup(catalog.Identity{ExeBasename: "curl", TeamID: "TESTTEAM"}, "api.example.com"); !got.Found {
		t.Fatal("user allow should be consulted when baseline is absent")
	}
	// A host only a baseline would have provided must not be found.
	if got := live.Lookup(catalog.Identity{ExeBasename: "updater", TeamID: "TESTTEAM"}, "updates.example.com"); got.Found {
		t.Fatal("no baseline installed, yet a baseline-only host matched")
	}
}

func TestLoadLayeredCatalog_MissingBothFilesIsEmptyCatalog(t *testing.T) {
	dir := t.TempDir()
	live, err := loadLayeredCatalog(
		filepath.Join(dir, "catalog-baseline.toml"),
		filepath.Join(dir, "catalog-user.toml"),
	)
	if err != nil {
		t.Fatalf("no files present must yield an empty catalog, not an error: %v", err)
	}
	if got := live.Lookup(catalog.Identity{ExeBasename: "anything"}, "anywhere.example.com"); got.Found {
		t.Fatal("empty catalog matched a lookup")
	}
}

func TestLoadLayeredCatalog_MalformedBaselineIsHardError(t *testing.T) {
	dir := t.TempDir()
	basePath := filepath.Join(dir, "catalog-baseline.toml")
	if err := os.WriteFile(basePath, []byte("this is not valid TOML {{{"), 0o644); err != nil {
		t.Fatalf("write malformed baseline: %v", err)
	}
	_, err := loadLayeredCatalog(basePath, filepath.Join(dir, "catalog-user.toml"))
	if err == nil {
		t.Fatal("a malformed baseline must be a hard error, not silently ignored")
	}
}

func TestBaselineCatalogPath_IsSiblingOfUserCatalog(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/tmp/xdg-test")
	base, err := baselineCatalogPath()
	if err != nil {
		t.Fatalf("baselineCatalogPath: %v", err)
	}
	user, err := userCatalogPath()
	if err != nil {
		t.Fatalf("userCatalogPath: %v", err)
	}
	if filepath.Dir(base) != filepath.Dir(user) {
		t.Fatalf("baseline (%s) and user (%s) catalogs must share a directory", base, user)
	}
	if filepath.Base(base) != "catalog-baseline.toml" {
		t.Fatalf("baseline filename = %q, want catalog-baseline.toml", filepath.Base(base))
	}
}
