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

func TestWriter_SameSecondRotationsDoNotOverwriteHistory(t *testing.T) {
	base := filepath.Join(t.TempDir(), "blocked.log")
	clock := time.Date(2026, 8, 15, 0, 0, 0, 0, time.UTC)
	w, err := OpenWithOptions(base, Options{
		MaxBytes: 200,
		Now:      func() time.Time { return clock },
	})
	if err != nil {
		t.Fatal(err)
	}
	const total = 400
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
		t.Fatalf("recovered %d of %d entries -- same-second rotation overwrote a segment", len(got), total)
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

func TestCompressSegment_AtomicAndRemovesPlain(t *testing.T) {
	dir := t.TempDir()
	seg := filepath.Join(dir, "blocked.log.20260815T031422Z")
	writeLines(t, seg, []string{"archived.example"})

	if err := compressSegment(seg); err != nil {
		t.Fatalf("compressSegment: %v", err)
	}
	if _, err := os.Stat(seg); !os.IsNotExist(err) {
		t.Fatal("plain segment still present after compression")
	}
	if _, err := os.Stat(seg + ".gz.tmp"); !os.IsNotExist(err) {
		t.Fatal("temp file left behind")
	}
	got, err := readSegment(seg + ".gz")
	if err != nil {
		t.Fatalf("readSegment: %v", err)
	}
	if len(got) != 1 || got[0].Host != "archived.example" {
		t.Fatalf("got %+v, want one archived.example entry", got)
	}
}

func TestSweepUncompressed_CompressesCrashLeftovers(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "blocked.log")
	seg := base + ".20260815T031422Z"
	writeLines(t, seg, []string{"leftover.example"})

	if err := sweepUncompressed(base); err != nil {
		t.Fatalf("sweepUncompressed: %v", err)
	}
	if _, err := os.Stat(seg + ".gz"); err != nil {
		t.Fatalf("leftover segment was not compressed: %v", err)
	}
}

func TestPruneSegments_DeletesOldestBeyondMax(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "blocked.log")
	for _, stamp := range []string{"20260813T000000Z", "20260814T000000Z", "20260815T000000Z"} {
		writeGzLines(t, base+"."+stamp+".gz", []string{stamp})
	}

	if err := pruneSegments(base, 2); err != nil {
		t.Fatalf("pruneSegments: %v", err)
	}
	segs, err := findSegments(base)
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) != 2 {
		t.Fatalf("kept %d segments, want 2", len(segs))
	}
	if strings.Contains(segs[0], "20260813") {
		t.Fatal("pruneSegments deleted a newer segment instead of the oldest")
	}
}

func TestPruneSegments_ZeroMeansUnlimited(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "blocked.log")
	for _, stamp := range []string{"20260813T000000Z", "20260814T000000Z"} {
		writeGzLines(t, base+"."+stamp+".gz", []string{stamp})
	}
	if err := pruneSegments(base, 0); err != nil {
		t.Fatalf("pruneSegments: %v", err)
	}
	segs, err := findSegments(base)
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) != 2 {
		t.Fatalf("kept %d segments, want 2 -- zero must mean unlimited", len(segs))
	}
}

func TestWriter_CloseWaitsForCompression(t *testing.T) {
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
	for i := 0; i < 20; i++ {
		if err := w.Write(Entry{Decision: DecisionAllow, Host: "pypi.org"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	segs, err := findSegments(base)
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) == 0 {
		t.Fatal("expected rotated segments")
	}
	for _, s := range segs {
		if !strings.HasSuffix(s, ".gz") {
			t.Fatalf("segment %s not compressed after Close", s)
		}
	}
}
