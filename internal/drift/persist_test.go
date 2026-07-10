package drift

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/decisionlog"
)

func buildLearnedBaseline(t *testing.T, cat *catalog.Catalog) *Baseline {
	t.Helper()
	base := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)
	learned := []decisionlog.Entry{
		{Timestamp: base.Format(time.RFC3339), Decision: decisionlog.DecisionAllow, Exe: "/Applications/Slack.app/MacOS/Slack", TeamID: "TEAMSLACK", Host: "slack.com"},
		{Timestamp: base.AddDate(0, 0, 1).Format(time.RFC3339), Decision: decisionlog.DecisionAllow, Exe: "/Applications/Slack.app/MacOS/Slack", TeamID: "TEAMSLACK", Host: "slack.com"},
	}
	return BuildBaseline(cat, learned)
}

func TestBuildBaselineRecordsBuiltThrough(t *testing.T) {
	b := buildLearnedBaseline(t, nil)
	want := time.Date(2026, 6, 2, 9, 0, 0, 0, time.UTC)
	if !b.BuiltThrough().Equal(want) {
		t.Errorf("BuiltThrough() = %v, want %v", b.BuiltThrough(), want)
	}
}

func TestBaselineRoundTripPreservesClassification(t *testing.T) {
	b := buildLearnedBaseline(t, nil)
	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := b.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	loaded, err := LoadBaseline(path, nil)
	if err != nil {
		t.Fatalf("LoadBaseline: %v", err)
	}

	ts := time.Date(2026, 6, 5, 9, 0, 0, 0, time.UTC).Format(time.RFC3339)
	known := decisionlog.Entry{Timestamp: ts, Decision: decisionlog.DecisionAllow, Exe: "/Applications/Slack.app/MacOS/Slack", TeamID: "TEAMSLACK", Host: "slack.com"}
	novel := decisionlog.Entry{Timestamp: ts, Decision: decisionlog.DecisionAllow, Exe: "/tmp/mystery", Host: "slack.com"}
	if got := loaded.Classify(known); got.Class != ClassKnown {
		t.Errorf("loaded baseline: known pair classified %q, want %q", got.Class, ClassKnown)
	}
	if got := loaded.Classify(novel); got.Class != ClassDrift {
		t.Errorf("loaded baseline: novel identity classified %q, want %q", got.Class, ClassDrift)
	}
	if !loaded.BuiltThrough().Equal(b.BuiltThrough()) {
		t.Errorf("BuiltThrough not preserved: loaded %v, original %v", loaded.BuiltThrough(), b.BuiltThrough())
	}
}

func TestLoadBaselineReattachesCatalogNotSerialized(t *testing.T) {
	b := buildLearnedBaseline(t, nil)
	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := b.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	cat, err := catalog.Load([]byte(""))
	if err != nil {
		t.Fatalf("catalog.Load: %v", err)
	}
	if err := cat.Add(catalog.Entry{
		SchemaVersion:        catalog.CurrentSchemaVersion,
		Identity:             catalog.Identity{ExeBasename: "Chrome", TeamID: "TEAMCHROME"},
		ExpectedDestinations: []catalog.Destination{{Host: "google.com", Why: "sync"}},
		Explanation:          "Chrome talks to Google",
		Evidence:             "vendor docs",
		Confidence:           catalog.ConfidenceHigh,
		Layer:                "baseline",
	}); err != nil {
		t.Fatalf("cat.Add: %v", err)
	}
	loaded, err := LoadBaseline(path, cat)
	if err != nil {
		t.Fatalf("LoadBaseline: %v", err)
	}
	chrome := decisionlog.Entry{Timestamp: time.Date(2026, 6, 5, 9, 0, 0, 0, time.UTC).Format(time.RFC3339), Decision: decisionlog.DecisionAllow, Exe: "/Applications/Google Chrome.app/MacOS/Chrome", TeamID: "TEAMCHROME", Host: "google.com"}
	if got := loaded.Classify(chrome); got.Class != ClassKnown {
		t.Errorf("catalog re-attach failed: Chrome->google.com classified %q, want %q", got.Class, ClassKnown)
	}
}

func TestIsStaleDetectsNewerEntries(t *testing.T) {
	b := buildLearnedBaseline(t, nil)
	older := []decisionlog.Entry{{Timestamp: time.Date(2026, 6, 2, 8, 0, 0, 0, time.UTC).Format(time.RFC3339), Decision: decisionlog.DecisionAllow, Exe: "/x", Host: "h"}}
	newer := []decisionlog.Entry{{Timestamp: time.Date(2026, 6, 3, 0, 0, 0, 0, time.UTC).Format(time.RFC3339), Decision: decisionlog.DecisionAllow, Exe: "/x", Host: "h"}}
	if b.IsStale(older) {
		t.Errorf("IsStale(entries all <= BuiltThrough) = true, want false")
	}
	if !b.IsStale(newer) {
		t.Errorf("IsStale(entries after BuiltThrough) = false, want true")
	}
}

func TestLoadBaselineMissingFileIsNotExist(t *testing.T) {
	_, err := LoadBaseline(filepath.Join(t.TempDir(), "nope.json"), nil)
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("LoadBaseline(missing) err = %v, want os.ErrNotExist", err)
	}
}
