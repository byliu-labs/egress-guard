package decisionlog

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRead_ReturnsAllEntries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "decisions.log")
	w, _ := Open(path)
	_ = w.Write(Entry{Decision: DecisionAllow, Action: "allow", Host: "a.example"})
	_ = w.Write(Entry{Decision: DecisionDeny, Action: "deny", Host: "b.example"})
	_ = w.Write(Entry{Decision: DecisionObserve, Action: "deny", Host: "c.example"})
	w.Close()

	entries, err := Read(path)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("got %d entries, want 3", len(entries))
	}
	if entries[0].Host != "a.example" || entries[2].Host != "c.example" {
		t.Errorf("entries out of order: %+v", entries)
	}
}

func TestRead_EmptyFileReturnsNoEntries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "decisions.log")
	w, _ := Open(path)
	w.Close()

	entries, err := Read(path)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("got %d entries, want 0", len(entries))
	}
}

func TestRead_MissingFileReturnsError(t *testing.T) {
	_, err := Read(filepath.Join(t.TempDir(), "does-not-exist.log"))
	if err == nil {
		t.Fatal("Read on missing file: want error, got nil")
	}
	if !os.IsNotExist(errUnwrapForTest(err)) {
		t.Errorf("error should wrap os.ErrNotExist so callers can errors.Is-check it: %v", err)
	}
}

func TestReadFilter_FiltersByHost(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "decisions.log")
	w, _ := Open(path)
	_ = w.Write(Entry{Decision: DecisionAllow, Action: "allow", Host: "keep.example"})
	_ = w.Write(Entry{Decision: DecisionAllow, Action: "allow", Host: "drop.example"})
	w.Close()

	entries, err := ReadFilter(path, Filter{Host: "keep.example"})
	if err != nil {
		t.Fatalf("ReadFilter: %v", err)
	}
	if len(entries) != 1 || entries[0].Host != "keep.example" {
		t.Fatalf("entries = %+v, want exactly keep.example", entries)
	}
}

func TestReadFilter_FiltersByPID(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "decisions.log")
	w, _ := Open(path)
	_ = w.Write(Entry{Decision: DecisionAllow, Action: "allow", Host: "a.example", PID: 111})
	_ = w.Write(Entry{Decision: DecisionAllow, Action: "allow", Host: "b.example", PID: 222})
	w.Close()

	entries, err := ReadFilter(path, Filter{PID: 222})
	if err != nil {
		t.Fatalf("ReadFilter: %v", err)
	}
	if len(entries) != 1 || entries[0].Host != "b.example" {
		t.Fatalf("entries = %+v, want exactly PID 222's entry", entries)
	}
}

func TestReadFilter_FiltersByTimeRange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "decisions.log")
	w, _ := Open(path)
	_ = w.Write(Entry{Timestamp: "2026-01-01T00:00:00Z", Decision: DecisionAllow, Action: "allow", Host: "early.example"})
	_ = w.Write(Entry{Timestamp: "2026-01-02T00:00:00Z", Decision: DecisionAllow, Action: "allow", Host: "mid.example"})
	_ = w.Write(Entry{Timestamp: "2026-01-03T00:00:00Z", Decision: DecisionAllow, Action: "allow", Host: "late.example"})
	w.Close()

	since := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	until := time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC)
	entries, err := ReadFilter(path, Filter{Since: since, Until: until})
	if err != nil {
		t.Fatalf("ReadFilter: %v", err)
	}
	if len(entries) != 1 || entries[0].Host != "mid.example" {
		t.Fatalf("entries = %+v, want exactly mid.example", entries)
	}
}

func errUnwrapForTest(err error) error {
	type unwrapper interface{ Unwrap() error }
	for {
		u, ok := err.(unwrapper)
		if !ok {
			return err
		}
		err = u.Unwrap()
	}
}
