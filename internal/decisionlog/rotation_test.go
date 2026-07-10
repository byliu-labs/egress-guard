package decisionlog

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestWriter_ConcurrentWritesNoCorruption(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "decisions.log")
	w, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer w.Close()

	const goroutines = 20
	const perGoroutine = 50
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				_ = w.Write(Entry{
					Decision: DecisionAllow,
					Action:   "allow",
					Host:     fmt.Sprintf("g%d-h%d.example", g, i),
				})
			}
		}(g)
	}
	wg.Wait()

	entries, err := Read(path)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(entries) != goroutines*perGoroutine {
		t.Fatalf("got %d entries, want %d (lost or corrupted writes under concurrency)",
			len(entries), goroutines*perGoroutine)
	}
}

func TestWriter_SurvivesExternalRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "decisions.log")
	w, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer w.Close()

	const total = 200
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < total; i++ {
			_ = w.Write(Entry{Decision: DecisionDeny, Action: "deny", Host: fmt.Sprintf("h%d.example", i)})
		}
	}()

	time.Sleep(2 * time.Millisecond)
	rotated := filepath.Join(dir, "decisions.log.1")
	if err := os.Rename(path, rotated); err != nil {
		t.Fatalf("simulate rotation rename: %v", err)
	}
	wg.Wait()

	entries, err := Read(rotated)
	if err != nil {
		t.Fatalf("Read rotated file: %v", err)
	}
	if len(entries) != total {
		t.Fatalf("got %d entries in rotated file, want %d (rotation dropped or lost writes)",
			len(entries), total)
	}
}

func TestRead_TrailingCorruptLineIsSkipped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "decisions.log")
	w, _ := Open(path)
	_ = w.Write(Entry{Decision: DecisionAllow, Action: "allow", Host: "good.example"})
	w.Close()

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("open for torn append: %v", err)
	}
	if _, err := f.WriteString(`{"ts":"2026-01-01T00:00:00Z","decision":"al`); err != nil {
		t.Fatalf("write torn line: %v", err)
	}
	f.Close()

	entries, err := Read(path)
	if err != nil {
		t.Fatalf("Read: %v (trailing torn line should be tolerated)", err)
	}
	if len(entries) != 1 || entries[0].Host != "good.example" {
		t.Fatalf("entries = %+v, want exactly the one good entry", entries)
	}
}

func TestRead_MidFileCorruptionIsAnError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "decisions.log")
	content := "{\"ts\":\"2026-01-01T00:00:00Z\",\"decision\":\"allow\",\"action\":\"allow\",\"host\":\"a.example\"}\n" +
		"not-json-at-all\n" +
		"{\"ts\":\"2026-01-01T00:00:01Z\",\"decision\":\"allow\",\"action\":\"allow\",\"host\":\"b.example\"}\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if _, err := Read(path); err == nil {
		t.Error("expected Read to error on mid-file corruption, got nil")
	}
}
