package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInspect_ReportsConcurrencyOverAWrittenLog(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "decisions.log")

	// Two overlapping connections for one pair, written as the daemon writes
	// them: a decision record and a flow record sharing a conn_id.
	lines := strings.Join([]string{
		`{"ts":"2026-01-01T09:00:00Z","decision":"allow","kind":"decision","conn_id":"a","exe":"/usr/bin/git","comm":"git","host":"github.com"}`,
		`{"ts":"2026-01-01T09:00:01Z","decision":"allow","kind":"decision","conn_id":"b","exe":"/usr/bin/git","comm":"git","host":"github.com"}`,
		`{"ts":"2026-01-01T09:00:30Z","kind":"flow","conn_id":"a","bytes_up":100,"bytes_down":200,"duration_ms":30000}`,
		`{"ts":"2026-01-01T09:00:31Z","kind":"flow","conn_id":"b","bytes_up":100,"bytes_down":200,"duration_ms":30000}`,
	}, "\n") + "\n"
	if err := os.WriteFile(logPath, []byte(lines), 0o600); err != nil {
		t.Fatal(err)
	}

	rep, err := inspect(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Pairs == 0 {
		t.Fatal("no pairs built from a log that clearly contains one")
	}
	if rep.PointsWithConcurrency == 0 {
		t.Fatalf("%d points built and none carries concurrency; the retroactive "+
			"property does not hold on a real log file", rep.Points)
	}
}

func TestInspect_EmptyLogIsNotAnError(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "decisions.log")
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := inspect(p)
	if err != nil {
		t.Fatalf("an empty log must report zero, not error: %v", err)
	}
	if rep.Points != 0 {
		t.Errorf("Points = %d, want 0", rep.Points)
	}
}

func TestDefaultLogPathUsesDaemonResolution(t *testing.T) {
	stateHome := t.TempDir()
	t.Setenv("XDG_STATE_HOME", stateHome)

	got, err := defaultLogPath()
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(stateHome, "egress-guard", "blocked.log")
	if got != want {
		t.Errorf("defaultLogPath() = %q, want %q", got, want)
	}
}

func TestSelectedLogPathPreservesExplicitOverride(t *testing.T) {
	got, err := selectedLogPath("/tmp/alternative.log")
	if err != nil {
		t.Fatal(err)
	}
	if got != "/tmp/alternative.log" {
		t.Errorf("selectedLogPath() = %q, want explicit override", got)
	}
}

// The daemon rebuilds its baseline from decisionlog.ReadHistory, which spans
// rotated segments as well as the live file. This tool exists to verify that
// rebuild, so it must read the same history — reading only the live file makes
// it report a smaller, different baseline than the one the daemon actually
// holds, and on a rotated log it prints "no historical point carries
// concurrency" for a machine whose clouds do carry it.
func TestInspect_ReadsRotatedSegmentsLikeTheDaemon(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "blocked.log")

	// Yesterday's traffic, already rotated out: two overlapping connections.
	rotated := strings.Join([]string{
		`{"ts":"2026-01-01T09:00:00Z","decision":"allow","kind":"decision","conn_id":"s1","exe":"/usr/bin/git","comm":"git","host":"github.com"}`,
		`{"ts":"2026-01-01T09:00:00Z","decision":"allow","kind":"decision","conn_id":"s2","exe":"/usr/bin/git","comm":"git","host":"github.com"}`,
		`{"ts":"2026-01-01T09:00:30Z","kind":"flow","conn_id":"s1","bytes_up":100,"bytes_down":200,"duration_ms":30000}`,
		`{"ts":"2026-01-01T09:00:30Z","kind":"flow","conn_id":"s2","bytes_up":100,"bytes_down":200,"duration_ms":30000}`,
	}, "\n") + "\n"
	// Today's traffic, in the live file: one connection, overlapping nothing.
	current := strings.Join([]string{
		`{"ts":"2026-01-02T09:00:00Z","decision":"allow","kind":"decision","conn_id":"c1","exe":"/usr/bin/git","comm":"git","host":"github.com"}`,
		`{"ts":"2026-01-02T09:00:30Z","kind":"flow","conn_id":"c1","bytes_up":100,"bytes_down":200,"duration_ms":30000}`,
	}, "\n") + "\n"

	if err := os.WriteFile(live+".20260101T090000Z", []byte(rotated), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(live, []byte(current), 0o600); err != nil {
		t.Fatal(err)
	}

	rep, err := inspect(live)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Connections != 3 {
		t.Errorf("connections = %d, want 3: the rotated segment is history the daemon folds in", rep.Connections)
	}
	// The two overlapping connections live entirely in the rotated segment, so
	// a live-file-only read reports zero here and warns the derivation is broken.
	if rep.PointsWithConcurrency != 2 {
		t.Fatalf("points with concurrency = %d, want 2 from the rotated segment", rep.PointsWithConcurrency)
	}
}
