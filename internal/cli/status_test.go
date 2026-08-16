package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLogFootprint_CountsSegmentsAndLiveFile(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "blocked.log")
	if err := os.WriteFile(base, []byte("0123456789\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(base+".20260813T000000Z.gz", []byte("0123456789"), 0o644); err != nil {
		t.Fatal(err)
	}

	segs, bytes, err := logFootprint(base)
	if err != nil {
		t.Fatalf("logFootprint: %v", err)
	}
	if segs != 1 {
		t.Fatalf("segments = %d, want 1", segs)
	}
	if bytes != 21 {
		t.Fatalf("bytes = %d, want 21 (11 live + 10 archived)", bytes)
	}
}

func TestLogFootprint_SkipsInFlightTempFiles(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "blocked.log")
	if err := os.WriteFile(base, []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(base+".20260813T000000Z.gz.tmp", []byte("0123456789"), 0o644); err != nil {
		t.Fatal(err)
	}
	segs, bytes, err := logFootprint(base)
	if err != nil {
		t.Fatalf("logFootprint: %v", err)
	}
	if segs != 0 {
		t.Fatalf("segments = %d, want 0 -- a .gz.tmp is mid-compression, not a segment", segs)
	}
	if bytes != 2 {
		t.Fatalf("bytes = %d, want 2 (live file only)", bytes)
	}
}

func TestLogFootprint_IgnoresForeignSuffixes(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "blocked.log")
	if err := os.WriteFile(base+".old", []byte("0123456789"), 0o644); err != nil {
		t.Fatal(err)
	}

	segs, bytes, err := logFootprint(base)
	if err != nil {
		t.Fatalf("logFootprint: %v", err)
	}
	if segs != 0 || bytes != 0 {
		t.Fatalf("got (%d, %d), want (0, 0) -- .old is not a rotated decision-log segment", segs, bytes)
	}
}

func TestLogFootprint_MissingLogIsZeroNotError(t *testing.T) {
	segs, bytes, err := logFootprint(filepath.Join(t.TempDir(), "blocked.log"))
	if err != nil {
		t.Fatalf("logFootprint: %v", err)
	}
	if segs != 0 || bytes != 0 {
		t.Fatalf("got (%d, %d), want (0, 0)", segs, bytes)
	}
}
