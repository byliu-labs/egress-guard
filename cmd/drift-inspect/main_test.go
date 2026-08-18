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
