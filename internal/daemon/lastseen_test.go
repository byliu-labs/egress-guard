package daemon

import (
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/decisionlog"
	"github.com/byliu-labs/egress-guard/internal/drift"
)

// overCapacityBaseline builds a baseline with n distinct pairs, one per
// second, so callers can exercise the live cap.
func overCapacityBaseline(t *testing.T, n int) (*drift.Baseline, time.Time) {
	t.Helper()
	base := time.Date(2026, 8, 19, 0, 0, 0, 0, time.UTC)
	entries := make([]decisionlog.Entry, n)
	for i := range entries {
		entries[i] = decisionlog.Entry{
			Timestamp: base.Add(time.Duration(i) * time.Second).Format(time.RFC3339),
			Decision:  decisionlog.DecisionAllow,
			Exe:       "/usr/bin/curl",
			Host:      "host-" + strconv.Itoa(i) + ".example",
		}
	}
	return drift.BuildBaseline(&catalog.Catalog{}, entries), base
}

func TestLastSeen_AdvanceIsMonotonic(t *testing.T) {
	l := newLastSeen(8)
	later := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	l.advance("p", later)
	l.advance("p", later.Add(-time.Hour))
	if got := l.at("p"); !got.Equal(later) {
		t.Fatalf("at = %v, want %v", got, later)
	}
}

func TestLastSeen_EvictsLeastRecentlyAdvancedBeyondTheCap(t *testing.T) {
	l := newLastSeen(2)
	base := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	l.advance("a", base.Add(10*time.Minute))
	l.advance("b", base)
	l.advance("c", base.Add(20*time.Minute))
	if got := l.at("a"); !got.IsZero() {
		t.Errorf("least-recently-advanced pair a survived eviction: %v", got)
	}
	if got := l.at("c"); got.IsZero() {
		t.Error("c was evicted instead of a")
	}
}

func TestLastSeen_SeedingBeyondCapacityStaysBounded(t *testing.T) {
	l := newLastSeen(4096)
	base := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	started := time.Now()
	for i := 0; i < 20_000; i++ {
		l.advance(strconv.Itoa(i), base.Add(time.Duration(i)*time.Second))
	}
	// Deliberately loose. This guards an algorithmic class, not a benchmark:
	// the scan-for-minimum it replaced measures ~800ms here, so 500ms still
	// kills it by 16x. A tight bound flakes — the same loop measured 27ms and
	// 267ms on consecutive runs of the full `-race` suite on an idle laptop,
	// and a false "eviction is too expensive" is worse than no guard at all.
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("advancing 20,000 pairs took %v; eviction is too expensive", elapsed)
	}
}

// TestLastSeen_ReAdvancingAPairRescuesItFromEviction is the only test that
// re-advances an existing key, so it is the only thing that executes
// MoveToFront. Without it the map degrades to insertion-order FIFO and evicts
// the busiest pairs first — exactly the references worth keeping.
func TestLastSeen_ReAdvancingAPairRescuesItFromEviction(t *testing.T) {
	l := newLastSeen(2)
	base := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	l.advance("a", base)
	l.advance("b", base.Add(time.Minute))
	l.advance("a", base.Add(2*time.Minute)) // a is now the most recently advanced
	l.advance("c", base.Add(3*time.Minute))
	if got := l.at("a"); got.IsZero() {
		t.Error("re-advanced pair a was evicted; MoveToFront is not wired")
	}
	if got := l.at("b"); !got.IsZero() {
		t.Errorf("least-recently-advanced pair b survived eviction: %v", got)
	}
}

// TestLastSeen_SeedKeepsTheMostRecentlyActivePairs pins seed's insertion order.
// Baseline.Pairs ranges a map, so without the sort the surviving set is a
// different random 4096 every refresh.
func TestLastSeen_SeedRetainsNewestAndIsDeterministic(t *testing.T) {
	b, base := overCapacityBaseline(t, 6000)
	hot := decisionlog.Entry{
		Timestamp: base.Format(time.RFC3339), Decision: decisionlog.DecisionAllow,
		Exe: "/usr/bin/curl", Host: "host-0.example",
	}
	key := drift.BaselinePairKey(hot)

	// A pair a connection goroutine advanced seconds ago holds the newest
	// reference in the map. A refresh must not be what throws it away.
	live := newLastSeen(maxLiveLastSeenPairs)
	live.advance(key, base.Add(10*time.Hour))
	live.seed(b)
	if live.at(key).IsZero() {
		t.Error("seeding an over-capacity baseline evicted a just-served live pair")
	}

	snapshot := func() map[string]bool {
		l := newLastSeen(maxLiveLastSeenPairs)
		l.seed(b)
		l.mu.Lock()
		defer l.mu.Unlock()
		out := make(map[string]bool, len(l.when))
		for k := range l.when {
			out[k] = true
		}
		return out
	}
	first, second := snapshot(), snapshot()
	if len(first) != maxLiveLastSeenPairs {
		t.Fatalf("retained %d pairs, want the cap %d", len(first), maxLiveLastSeenPairs)
	}
	for k := range first {
		if !second[k] {
			t.Fatalf("two seeds of the same baseline retained different pairs (e.g. %q); retention is nondeterministic", k)
		}
	}
}

func TestLastSeen_CountsEvictions(t *testing.T) {
	l := newLastSeen(2)
	base := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	if got := l.evictionCount(); got != 0 {
		t.Fatalf("evictions after construction = %d, want 0", got)
	}
	l.advance("a", base)
	l.advance("b", base.Add(time.Minute))
	if got := l.evictionCount(); got != 0 {
		t.Fatalf("evictions at capacity = %d, want 0", got)
	}
	l.advance("c", base.Add(2*time.Minute))
	if got := l.evictionCount(); got != 1 {
		t.Fatalf("evictions after exceeding capacity = %d, want 1", got)
	}
}

func TestLastSeen_ConcurrentAdvanceIsRaceFree(t *testing.T) {
	l := newLastSeen(64)
	base := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			l.advance("p", base.Add(time.Duration(i)*time.Second))
			_ = l.at("p")
		}(i)
	}
	wg.Wait()
	if got := l.at("p"); !got.Equal(base.Add(49 * time.Second)) {
		t.Fatalf("at = %v, want the newest write", got)
	}
}

func TestLastSeen_AdvanceEntryMatchesBaselineFolding(t *testing.T) {
	l := newLastSeen(8)
	denied := decisionlog.Entry{
		Timestamp: "2026-08-19T12:00:00Z", Decision: decisionlog.DecisionDeny,
		Exe: "/usr/bin/curl", Host: "deny.example",
	}
	l.advanceEntry(denied)
	if got := l.at(drift.BaselinePairKey(denied)); !got.IsZero() {
		t.Fatalf("denial advanced reference to %v", got)
	}

	flowless := decisionlog.Entry{
		Timestamp: "2026-08-19T12:01:00Z", Decision: decisionlog.DecisionAllow,
		Exe: "/usr/bin/curl", Host: "allow.example",
	}
	l.advanceEntry(flowless)
	if got := l.at(drift.BaselinePairKey(flowless)); got.IsZero() {
		t.Fatal("flowless accepted connection did not advance reference")
	}
}

func TestLastSeen_SeedKeepsTheNewerReference(t *testing.T) {
	decision := decisionlog.Entry{
		Kind: decisionlog.KindDecision, ConnID: "old", Timestamp: "2026-08-19T12:00:00Z",
		Decision: decisionlog.DecisionAllow, Exe: "/usr/bin/curl", Host: "allow.example",
	}
	key := drift.BaselinePairKey(decision)
	live := time.Date(2026, 8, 19, 12, 30, 0, 0, time.UTC)
	l := newLastSeen(8)
	l.advance(key, live)
	l.seed(drift.BuildBaseline(&catalog.Catalog{}, []decisionlog.Entry{decision}))
	if got := l.at(key); !got.Equal(live) {
		t.Fatalf("seed rolled the live reference back to %v", got)
	}
}
