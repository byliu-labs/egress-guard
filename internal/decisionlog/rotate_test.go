package decisionlog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWriter_RotatesPastMaxBytes(t *testing.T) {
	base := filepath.Join(t.TempDir(), "blocked.log")
	clock := time.Date(2026, 8, 15, 3, 14, 22, 0, time.UTC)
	w, err := OpenWithOptions(base, Options{
		MaxBytes: 200,
		Now:      func() time.Time { return clock },
	})
	if err != nil {
		t.Fatalf("OpenWithOptions: %v", err)
	}
	defer w.Close()

	for i := 0; i < 6; i++ {
		if err := w.Write(Entry{Decision: DecisionAllow, Host: "pypi.org"}); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	segs, err := findSegments(base)
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) == 0 {
		t.Fatal("no segment created; writer never rotated past MaxBytes")
	}
	fi, err := os.Stat(base)
	if err != nil {
		t.Fatalf("live file missing after rotation: %v", err)
	}
	if fi.Size() > 200 {
		t.Fatalf("live file is %d bytes, want <= MaxBytes after rotation", fi.Size())
	}
}

func TestWriter_NoEntryLostAcrossRotation(t *testing.T) {
	base := filepath.Join(t.TempDir(), "blocked.log")
	n := 0
	w, err := OpenWithOptions(base, Options{
		MaxBytes: 200,
		Now: func() time.Time {
			n++
			return time.Date(2026, 8, 15, 0, 0, n, 0, time.UTC)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	const total = 20
	for i := 0; i < total; i++ {
		if err := w.Write(Entry{Decision: DecisionAllow, Host: "pypi.org"}); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	got, err := ReadHistory(base)
	if err != nil {
		t.Fatalf("ReadHistory: %v", err)
	}
	if len(got) != total {
		t.Fatalf("ReadHistory returned %d entries, want %d -- rotation dropped history", len(got), total)
	}
}

func TestOpen_DefaultsToRotationOnAndRetentionUnlimited(t *testing.T) {
	base := filepath.Join(t.TempDir(), "blocked.log")
	w, err := Open(base)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if w.opts.MaxBytes != DefaultMaxBytes {
		t.Fatalf("Open MaxBytes = %d, want DefaultMaxBytes %d", w.opts.MaxBytes, DefaultMaxBytes)
	}
	if w.opts.MaxSegments != 0 {
		t.Fatalf("Open MaxSegments = %d, want 0 (unlimited retention by default)", w.opts.MaxSegments)
	}
}

func TestWriter_NegativeMaxBytesDisablesRotation(t *testing.T) {
	base := filepath.Join(t.TempDir(), "blocked.log")
	w, err := OpenWithOptions(base, Options{MaxBytes: -1})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	for i := 0; i < 50; i++ {
		if err := w.Write(Entry{Decision: DecisionAllow, Host: "pypi.org"}); err != nil {
			t.Fatal(err)
		}
	}
	segs, err := findSegments(base)
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) != 0 {
		t.Fatalf("rotated %d segments with MaxBytes=-1, want 0", len(segs))
	}
}

func TestWriter_SizeSeededFromExistingFile(t *testing.T) {
	base := filepath.Join(t.TempDir(), "blocked.log")
	if err := os.WriteFile(base, []byte(strings.Repeat("x", 300)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	w, err := OpenWithOptions(base, Options{MaxBytes: 200})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if err := w.Write(Entry{Decision: DecisionAllow, Host: "pypi.org"}); err != nil {
		t.Fatal(err)
	}
	segs, err := findSegments(base)
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) == 0 {
		t.Fatal("writer did not seed its size from the pre-existing file, so it never rotated")
	}
}
