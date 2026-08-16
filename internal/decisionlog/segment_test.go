package decisionlog

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSegmentName_IsFixedWidthUTC(t *testing.T) {
	got := segmentName("/var/log/blocked.log", time.Date(2026, 8, 15, 3, 14, 22, 0, time.UTC))
	want := "/var/log/blocked.log.20260815T031422Z"
	if got != want {
		t.Fatalf("segmentName = %q, want %q", got, want)
	}
}

func TestFindSegments_OldestFirstAndPrefersGzip(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "blocked.log")
	for _, n := range []string{
		"blocked.log",
		"blocked.log.20260814T010000Z.gz",
		"blocked.log.20260815T031422Z",
		"blocked.log.20260815T031422Z.gz",
	} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	got, err := findSegments(base)
	if err != nil {
		t.Fatalf("findSegments: %v", err)
	}
	want := []string{
		filepath.Join(dir, "blocked.log.20260814T010000Z.gz"),
		filepath.Join(dir, "blocked.log.20260815T031422Z.gz"),
	}
	if len(got) != len(want) {
		t.Fatalf("findSegments = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("findSegments[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestFindSegments_IgnoresForeignSuffixes(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "blocked.log")
	for _, n := range []string{"blocked.log.old", "blocked.log.1", "blocked.log.20260815T031422Z.gz.tmp"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := findSegments(base)
	if err != nil {
		t.Fatalf("findSegments: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("findSegments = %v, want empty (none of those are our segments)", got)
	}
}

func TestFindSegments_NoSegmentsIsEmptyNotError(t *testing.T) {
	base := filepath.Join(t.TempDir(), "blocked.log")
	got, err := findSegments(base)
	if err != nil {
		t.Fatalf("findSegments: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("findSegments = %v, want empty", got)
	}
}
