package cli

import (
	"path/filepath"
	"testing"

	"github.com/byliu-labs/egress-guard/internal/catalog"
)

func TestCatalogRatifyWriter_WritesFileAndUpdatesLiveCatalog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "catalog-user.toml")
	live := &catalog.Catalog{}
	w := newCatalogRatifyWriter(path, live)

	entry := catalog.Entry{
		SchemaVersion:        catalog.CurrentSchemaVersion,
		Identity:             catalog.Identity{ExeBasename: "driftapp", TeamID: "TEAMX"},
		ExpectedDestinations: []catalog.Destination{{Host: "driftapp.io", Why: "test"}},
		Explanation:          "test entry",
		Evidence:             "test evidence",
		Confidence:           catalog.ConfidenceHigh,
		Layer:                "user",
	}
	if err := w.Ratify(entry); err != nil {
		t.Fatalf("Ratify: %v", err)
	}

	onDisk, err := catalog.LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile after Ratify: %v", err)
	}
	id := catalog.Identity{ExeBasename: "driftapp", TeamID: "TEAMX"}
	if !onDisk.Lookup(id, "driftapp.io").Found {
		t.Error("on-disk catalog does not contain the ratified entry")
	}
	if !live.Lookup(id, "driftapp.io").Found {
		t.Error("live catalog was not updated by Ratify")
	}
}

func TestCatalogRatifyWriter_AppendsToExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "catalog-user.toml")
	live := &catalog.Catalog{}
	w := newCatalogRatifyWriter(path, live)

	first := catalog.Entry{
		SchemaVersion:        catalog.CurrentSchemaVersion,
		Identity:             catalog.Identity{ExeBasename: "appone", TeamID: "TEAM1"},
		ExpectedDestinations: []catalog.Destination{{Host: "one.example", Why: "t"}},
		Explanation:          "one",
		Evidence:             "e1",
		Confidence:           catalog.ConfidenceHigh,
		Layer:                "user",
	}
	second := catalog.Entry{
		SchemaVersion:        catalog.CurrentSchemaVersion,
		Identity:             catalog.Identity{ExeBasename: "apptwo", TeamID: "TEAM2"},
		ExpectedDestinations: []catalog.Destination{{Host: "two.example", Why: "t"}},
		Explanation:          "two",
		Evidence:             "e2",
		Confidence:           catalog.ConfidenceHigh,
		Layer:                "user",
	}
	if err := w.Ratify(first); err != nil {
		t.Fatalf("Ratify(first): %v", err)
	}
	if err := w.Ratify(second); err != nil {
		t.Fatalf("Ratify(second): %v", err)
	}

	onDisk, err := catalog.LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if !onDisk.Lookup(catalog.Identity{ExeBasename: "appone", TeamID: "TEAM1"}, "one.example").Found {
		t.Error("first ratified entry lost after second Ratify call")
	}
	if !onDisk.Lookup(catalog.Identity{ExeBasename: "apptwo", TeamID: "TEAM2"}, "two.example").Found {
		t.Error("second ratified entry missing")
	}
}

func TestUserCatalogPath_UsesResolvedHome(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", "/tmp/test-home")
	got, err := userCatalogPath()
	if err != nil {
		t.Fatalf("userCatalogPath: %v", err)
	}
	want := filepath.Join("/tmp/test-home", ".config", "egress-guard", "catalog-user.toml")
	if got != want {
		t.Errorf("userCatalogPath = %q, want %q", got, want)
	}
}
