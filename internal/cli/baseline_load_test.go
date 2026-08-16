package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/decisionlog"
	"github.com/byliu-labs/egress-guard/internal/drift"
)

// writeLog writes the given entries as JSONL at path (timestamps preserved).
func writeLog(t *testing.T, path string, entries []decisionlog.Entry) {
	t.Helper()
	w, err := decisionlog.Open(path)
	if err != nil {
		t.Fatalf("open log: %v", err)
	}
	for _, e := range entries {
		if err := w.Write(e); err != nil {
			t.Fatalf("write entry: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close log: %v", err)
	}
}

// logAllow builds an allow decision-log entry for exe→host at a fixed RFC3339 day.
func logAllow(exe, host, ts string) decisionlog.Entry {
	return decisionlog.Entry{
		Timestamp: ts,
		Decision:  decisionlog.DecisionAllow,
		Action:    "allow",
		Exe:       exe,
		Host:      host,
	}
}

type capLogger struct{ msgs []string }

func (c *capLogger) Errorf(format string, args ...any) {
	c.msgs = append(c.msgs, format)
}

// A pair seen on two distinct UTC days enters the baseline (minStableDays=2).
func twoDayPair(exe, host string) []decisionlog.Entry {
	return []decisionlog.Entry{
		logAllow(exe, host, "2026-07-01T10:00:00Z"),
		logAllow(exe, host, "2026-07-02T10:00:00Z"),
	}
}

func TestLoadOrBuildBaseline_MissingLogAndCacheIsEmpty(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "blocked.log")
	cachePath := filepath.Join(dir, "baseline.json")

	b, err := loadOrBuildBaseline(logPath, cachePath, &catalog.Catalog{}, &capLogger{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if b == nil {
		t.Fatal("expected an empty baseline, got nil")
	}
	// Cache file must have been written on rebuild.
	if _, err := drift.LoadBaseline(cachePath, &catalog.Catalog{}); err != nil {
		t.Fatalf("expected cache written, load failed: %v", err)
	}
}

func TestLoadOrBuildBaseline_BuildsFromLog(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "blocked.log")
	cachePath := filepath.Join(dir, "baseline.json")
	writeLog(t, logPath, twoDayPair("/usr/bin/curl", "api.example.com"))

	b, err := loadOrBuildBaseline(logPath, cachePath, &catalog.Catalog{}, &capLogger{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ev := b.Classify(logAllow("/usr/bin/curl", "api.example.com", "2026-07-03T10:00:00Z"))
	if ev.Class != drift.ClassKnown {
		t.Fatalf("expected learned pair known, got class=%q reason=%q", ev.Class, ev.Reason)
	}
}

func TestLoadOrBuildBaseline_SkipsCorruptRotatedSegment(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "blocked.log")
	cachePath := filepath.Join(dir, "baseline.json")
	writeLog(t, logPath+".20260701T100000Z", []decisionlog.Entry{
		logAllow("/usr/bin/curl", "api.example.com", "2026-07-01T10:00:00Z"),
	})
	if err := os.WriteFile(logPath+".20260702T100000Z.gz", []byte("not gzip"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeLog(t, logPath, []decisionlog.Entry{
		logAllow("/usr/bin/curl", "api.example.com", "2026-07-02T10:00:00Z"),
	})

	b, err := loadOrBuildBaseline(logPath, cachePath, &catalog.Catalog{}, &capLogger{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ev := b.Classify(logAllow("/usr/bin/curl", "api.example.com", "2026-07-03T10:00:00Z"))
	if ev.Class != drift.ClassKnown {
		t.Fatalf("expected learned pair known despite one corrupt segment, got class=%q reason=%q", ev.Class, ev.Reason)
	}
}

func TestLoadOrBuildBaseline_FreshCacheIsNotRebuilt(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "blocked.log")
	cachePath := filepath.Join(dir, "baseline.json")

	// Seed a cache knowing a pair (built through 2026-07-05) NOT in the log.
	seeded := drift.BuildBaseline(&catalog.Catalog{}, []decisionlog.Entry{
		logAllow("/usr/bin/git", "github.com", "2026-07-04T10:00:00Z"),
		logAllow("/usr/bin/git", "github.com", "2026-07-05T10:00:00Z"),
	})
	if err := seeded.Save(cachePath); err != nil {
		t.Fatalf("seed cache: %v", err)
	}
	// Log has only OLDER traffic (2026-07-01/02) → cache is not stale.
	writeLog(t, logPath, twoDayPair("/usr/bin/curl", "api.example.com"))

	b, err := loadOrBuildBaseline(logPath, cachePath, &catalog.Catalog{}, &capLogger{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Cache honored (not rebuilt): the cache-only pair is known...
	if ev := b.Classify(logAllow("/usr/bin/git", "github.com", "2026-07-06T10:00:00Z")); ev.Class != drift.ClassKnown {
		t.Fatalf("expected cached pair known (cache honored), got %q", ev.Class)
	}
	// ...and the log-only pair is NOT known (never folded).
	if ev := b.Classify(logAllow("/usr/bin/curl", "api.example.com", "2026-07-06T10:00:00Z")); ev.Class != drift.ClassDrift {
		t.Fatalf("expected log-only pair unknown (cache honored), got %q", ev.Class)
	}
}

func TestLoadOrBuildBaseline_StaleCacheRebuilds(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "blocked.log")
	cachePath := filepath.Join(dir, "baseline.json")

	// Cache built through 2026-07-02.
	seeded := drift.BuildBaseline(&catalog.Catalog{}, twoDayPair("/usr/bin/git", "github.com"))
	if err := seeded.Save(cachePath); err != nil {
		t.Fatalf("seed cache: %v", err)
	}
	// Log contains NEWER traffic (2026-07-08/09) → cache stale → rebuild.
	writeLog(t, logPath, []decisionlog.Entry{
		logAllow("/usr/bin/curl", "api.example.com", "2026-07-08T10:00:00Z"),
		logAllow("/usr/bin/curl", "api.example.com", "2026-07-09T10:00:00Z"),
	})

	b, err := loadOrBuildBaseline(logPath, cachePath, &catalog.Catalog{}, &capLogger{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ev := b.Classify(logAllow("/usr/bin/curl", "api.example.com", "2026-07-10T10:00:00Z")); ev.Class != drift.ClassKnown {
		t.Fatalf("expected rebuilt-from-log pair known, got %q", ev.Class)
	}
}

func TestLoadStartupBaseline_DegradesToNilOnError(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "blocked.log")
	cachePath := filepath.Join(dir, "baseline.json")
	// A corrupt NON-final line makes decisionlog.Read (and thus
	// loadOrBuildBaseline) return an error — the firewall must still start.
	if err := os.WriteFile(logPath, []byte("garbage-not-json\n{\"ts\":\"2026-07-02T10:00:00Z\"}\n"), 0o644); err != nil {
		t.Fatalf("seed corrupt log: %v", err)
	}

	logger := &capLogger{}
	b := loadStartupBaseline(logPath, cachePath, &catalog.Catalog{}, logger)
	if b != nil {
		t.Fatal("a build error must degrade to a nil baseline, not a partial one")
	}
	if len(logger.msgs) == 0 {
		t.Fatal("expected the startup build failure to be logged")
	}
}

func TestLoadStartupBaseline_ReturnsBaselineOnSuccess(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "blocked.log")
	cachePath := filepath.Join(dir, "baseline.json")
	writeLog(t, logPath, twoDayPair("/usr/bin/curl", "api.example.com"))

	b := loadStartupBaseline(logPath, cachePath, &catalog.Catalog{}, &capLogger{})
	if b == nil {
		t.Fatal("expected a baseline on a clean build")
	}
	if ev := b.Classify(logAllow("/usr/bin/curl", "api.example.com", "2026-07-03T10:00:00Z")); ev.Class != drift.ClassKnown {
		t.Fatalf("expected learned pair known, got %q", ev.Class)
	}
}

func TestLoadOrBuildBaseline_CorruptCacheLogsAndRebuilds(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "blocked.log")
	cachePath := filepath.Join(dir, "baseline.json")
	if err := os.WriteFile(cachePath, []byte("{not valid json"), 0o644); err != nil {
		t.Fatalf("seed corrupt cache: %v", err)
	}
	writeLog(t, logPath, twoDayPair("/usr/bin/curl", "api.example.com"))

	logger := &capLogger{}
	b, err := loadOrBuildBaseline(logPath, cachePath, &catalog.Catalog{}, logger)
	if err != nil {
		t.Fatalf("corrupt cache must not error, got: %v", err)
	}
	if len(logger.msgs) == 0 {
		t.Fatal("expected a logged warning about the unreadable cache")
	}
	if ev := b.Classify(logAllow("/usr/bin/curl", "api.example.com", "2026-07-03T10:00:00Z")); ev.Class != drift.ClassKnown {
		t.Fatalf("expected rebuilt pair known, got %q", ev.Class)
	}
}
