package cli

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/drift"
)

type fakeSetter struct {
	mu     sync.Mutex
	calls  int
	last   *drift.Baseline
	gotOne chan struct{}
}

func newFakeSetter() *fakeSetter { return &fakeSetter{gotOne: make(chan struct{}, 1)} }

func (f *fakeSetter) SetBaseline(b *drift.Baseline) {
	f.mu.Lock()
	f.calls++
	f.last = b
	f.mu.Unlock()
	select {
	case f.gotOne <- struct{}{}:
	default:
	}
}

// safeLogger is a race-safe capturing logger for the concurrent refresher.
type safeLogger struct {
	mu   sync.Mutex
	msgs []string
}

func (l *safeLogger) Errorf(format string, args ...any) {
	l.mu.Lock()
	l.msgs = append(l.msgs, format)
	l.mu.Unlock()
}

func (l *safeLogger) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.msgs)
}

// TestRunBaselineRefresher_FailedRebuildKeepsLastGood proves the safety-critical
// invariant asserted in runBaselineRefresher's comment: when a rebuild fails, the
// refresher logs and skips — it never swaps in a bad baseline (setter is never
// called), so the daemon keeps its last-good baseline and enforcement is unharmed.
func TestRunBaselineRefresher_FailedRebuildKeepsLastGood(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "blocked.log")
	cachePath := filepath.Join(dir, "baseline.json")
	// Corrupt NON-final line → loadOrBuildBaseline errors on every tick.
	if err := os.WriteFile(logPath, []byte("garbage-not-json\n{\"ts\":\"2026-07-02T10:00:00Z\"}\n"), 0o644); err != nil {
		t.Fatalf("seed corrupt log: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	setter := newFakeSetter()
	logger := &safeLogger{}
	go runBaselineRefresher(ctx, setter, logPath, cachePath, &catalog.Catalog{},
		5*time.Millisecond, make(chan os.Signal), logger)

	// Let the refresher attempt several rebuilds.
	deadline := time.Now().Add(2 * time.Second)
	for logger.count() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()

	if logger.count() == 0 {
		t.Fatal("expected failed rebuilds to be logged")
	}
	setter.mu.Lock()
	calls := setter.calls
	setter.mu.Unlock()
	if calls != 0 {
		t.Fatalf("failed rebuild must never swap the baseline; got %d SetBaseline calls", calls)
	}
}

func TestRunBaselineRefresher_TickerRefreshes(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "blocked.log")
	cachePath := filepath.Join(dir, "baseline.json")
	writeLog(t, logPath, twoDayPair("/usr/bin/curl", "api.example.com"))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	setter := newFakeSetter()
	refresh := make(chan os.Signal, 1)

	go runBaselineRefresher(ctx, setter, logPath, cachePath, &catalog.Catalog{},
		10*time.Millisecond, refresh, &capLogger{})

	select {
	case <-setter.gotOne:
	case <-time.After(2 * time.Second):
		t.Fatal("ticker did not trigger a baseline refresh within 2s")
	}
	setter.mu.Lock()
	got := setter.last
	setter.mu.Unlock()
	if got == nil {
		t.Fatal("refresher stored a nil baseline")
	}
}

func TestRunBaselineRefresher_SignalRefreshes(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "blocked.log")
	cachePath := filepath.Join(dir, "baseline.json")
	writeLog(t, logPath, twoDayPair("/usr/bin/curl", "api.example.com"))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	setter := newFakeSetter()
	refresh := make(chan os.Signal, 1)

	// Long ticker so only the signal can trigger within the test window.
	go runBaselineRefresher(ctx, setter, logPath, cachePath, &catalog.Catalog{},
		time.Hour, refresh, &capLogger{})

	refresh <- syscall.SIGHUP
	select {
	case <-setter.gotOne:
	case <-time.After(2 * time.Second):
		t.Fatal("SIGHUP did not trigger a baseline refresh within 2s")
	}
}

func TestRunBaselineRefresher_StopsOnContextCancel(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "blocked.log")
	cachePath := filepath.Join(dir, "baseline.json")
	writeLog(t, logPath, twoDayPair("/usr/bin/curl", "api.example.com"))

	ctx, cancel := context.WithCancel(context.Background())
	setter := newFakeSetter()
	refresh := make(chan os.Signal, 1)

	done := make(chan struct{})
	go func() {
		runBaselineRefresher(ctx, setter, logPath, cachePath, &catalog.Catalog{},
			time.Hour, refresh, &capLogger{})
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("refresher did not return after context cancel")
	}
}
