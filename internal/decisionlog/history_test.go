package decisionlog

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func writeLines(t *testing.T, path string, hosts []string) {
	t.Helper()
	var buf []byte
	for _, h := range hosts {
		b, err := json.Marshal(Entry{Timestamp: "2026-08-15T03:14:22Z", Decision: DecisionAllow, Host: h})
		if err != nil {
			t.Fatal(err)
		}
		buf = append(append(buf, b...), '\n')
	}
	if err := os.WriteFile(path, buf, 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeGzLines(t *testing.T, path string, hosts []string) {
	t.Helper()
	plain := path + ".plainsrc"
	writeLines(t, plain, hosts)
	raw, err := os.ReadFile(plain)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := gzip.NewWriter(f)
	if _, err := zw.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(plain); err != nil {
		t.Fatal(err)
	}
}

func TestReadHistory_ConcatenatesOldestFirst(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "blocked.log")
	writeGzLines(t, base+".20260814T010000Z.gz", []string{"oldest.example"})
	writeLines(t, base+".20260815T031422Z", []string{"middle.example"})
	writeLines(t, base, []string{"live.example"})

	got, err := ReadHistory(base)
	if err != nil {
		t.Fatalf("ReadHistory: %v", err)
	}
	want := []string{"oldest.example", "middle.example", "live.example"}
	if len(got) != len(want) {
		t.Fatalf("got %d entries, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Host != want[i] {
			t.Fatalf("entry %d host = %q, want %q", i, got[i].Host, want[i])
		}
	}
}

func TestReadHistory_MissingLiveFileWithSegmentsIsNotAnError(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "blocked.log")
	writeGzLines(t, base+".20260814T010000Z.gz", []string{"archived.example"})

	got, err := ReadHistory(base)
	if err != nil {
		t.Fatalf("ReadHistory: %v", err)
	}
	if len(got) != 1 || got[0].Host != "archived.example" {
		t.Fatalf("got %+v, want one archived.example entry", got)
	}
}

func TestReadHistory_NothingOnDiskReportsNotExist(t *testing.T) {
	base := filepath.Join(t.TempDir(), "blocked.log")
	_, err := ReadHistory(base)
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("err = %v, want it to wrap os.ErrNotExist", err)
	}
}
