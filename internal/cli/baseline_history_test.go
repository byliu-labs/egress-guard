package cli

import (
	"path/filepath"
	"testing"

	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/decisionlog"
	"github.com/byliu-labs/egress-guard/internal/drift"
)

func writeEntriesTo(t *testing.T, path string, entries ...decisionlog.Entry) {
	t.Helper()
	w, err := decisionlog.OpenWithOptions(path, decisionlog.Options{MaxBytes: -1})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if err := w.Write(e); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestLoadOrBuildBaseline_CountsRotatedHistory(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "blocked.log")
	cachePath := filepath.Join(dir, "baseline.json")

	entry := func(ts string) decisionlog.Entry {
		return decisionlog.Entry{
			Timestamp: ts,
			Decision:  decisionlog.DecisionAllow,
			Exe:       "/usr/bin/curl",
			Host:      "pypi.org",
		}
	}

	writeEntriesTo(t, logPath+".20260813T000000Z", entry("2026-08-13T10:00:00Z"))
	writeEntriesTo(t, logPath, entry("2026-08-14T10:00:00Z"))

	cat, err := catalog.Load([]byte{})
	if err != nil {
		t.Fatal(err)
	}

	b, err := loadOrBuildBaseline(logPath, cachePath, cat, nil)
	if err != nil {
		t.Fatalf("loadOrBuildBaseline: %v", err)
	}

	ev := b.Classify(entry("2026-08-15T10:00:00Z"))
	if ev.Class != drift.ClassKnown {
		t.Fatalf("pair classified %q, want %q -- the rotated day was not counted, so an established pair was demoted to novel", ev.Class, drift.ClassKnown)
	}
}
