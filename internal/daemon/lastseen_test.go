package daemon

import (
	"reflect"
	"sort"
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
	base := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	fill := func(pairs int) time.Duration {
		l := newLastSeen(4096)
		started := time.Now()
		for i := 0; i < pairs; i++ {
			l.advance(strconv.Itoa(i), base.Add(time.Duration(i)*time.Second))
		}
		return time.Since(started)
	}
	// A wall-clock ceiling cannot work here: the same loop measured 27ms and
	// 267ms on consecutive runs of the full -race suite on an idle laptop, so
	// any bound tight enough to catch the scan is loose enough to flake. Ratio
	// against an eviction-free fill on the same machine, in the same run,
	// absorbs that. Observed ~5x with O(1) eviction; the scan-for-minimum this
	// replaced is ~1400x, so 50x has an order of magnitude of margin on both
	// sides.
	atCapacity, overCapacity := fill(4096), fill(20_000)
	if ratio := float64(overCapacity) / float64(atCapacity); ratio > 50 {
		t.Fatalf("20,000 pairs cost %v against %v at capacity (%.0fx); eviction is not O(1)",
			overCapacity, atCapacity, ratio)
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

// TestLastSeen_SeedRetainsNewestAndIsDeterministic pins seed's retention order.
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
	// Timestamp order and key order disagree here on purpose: host-5999 is the
	// newest pair but sorts late lexicographically, and host-1 is nearly the
	// oldest but sorts early. Retention must follow the clock, not the name.
	newest := drift.BaselinePairKey(decisionlog.Entry{
		Timestamp: base.Add(5999 * time.Second).Format(time.RFC3339), Decision: decisionlog.DecisionAllow,
		Exe: "/usr/bin/curl", Host: "host-5999.example",
	})
	oldest := drift.BaselinePairKey(decisionlog.Entry{
		Timestamp: base.Add(time.Second).Format(time.RFC3339), Decision: decisionlog.DecisionAllow,
		Exe: "/usr/bin/curl", Host: "host-1.example",
	})
	if !first[newest] {
		t.Error("the newest pair was evicted; retention is not ordered by reference time")
	}
	if first[oldest] {
		t.Error("an oldest-decile pair was retained over newer ones; retention is not ordered by reference time")
	}
	for k := range first {
		if !second[k] {
			t.Fatalf("two seeds of the same baseline retained different pairs (e.g. %q); retention is nondeterministic", k)
		}
	}
}

// TestLastSeen_SeedBoundsWorkDoneUnderTheLock pins the reduction that happens
// before seed takes the lock. at() sits inline on connection setup, and the
// baseline carries one pair per distinct (identity, host) the machine has ever
// logged, so a locked section that scales with history stalls every new TLS
// connection — measured at 167ms for 100k pairs before the reduction.
//
// Asserted on the count rather than the clock deliberately. The stall is a
// single event among ~1M at() samples, so every percentile stays flat and only
// the maximum moves; a timing bound compares max-of-N against max-of-14N drawn
// from a heavy-tailed distribution and reads whichever way the scheduler
// hiccuped — measured going the wrong way on 2 of 3 runs.
func TestLastSeen_SeedBoundsWorkDoneUnderTheLock(t *testing.T) {
	for _, pairs := range []int{2 * maxLiveLastSeenPairs, 25 * maxLiveLastSeenPairs} {
		b, _ := overCapacityBaseline(t, pairs)
		l := newLastSeen(maxLiveLastSeenPairs)
		l.seed(b)
		if l.seedLockedPairs != maxLiveLastSeenPairs {
			t.Errorf("a %d-pair snapshot carried %d pairs into the locked section; want at most the %d-pair cap",
				pairs, l.seedLockedPairs, maxLiveLastSeenPairs)
		}
	}
	// A snapshot below the cap is bounded by its own size, not padded to it.
	small, _ := overCapacityBaseline(t, 64)
	l := newLastSeen(maxLiveLastSeenPairs)
	l.seed(small)
	if l.seedLockedPairs != 64 {
		t.Errorf("64-pair snapshot carried %d pairs into the locked section, want 64", l.seedLockedPairs)
	}
}

// TestLastSeen_RepeatedSeedsKeepTheThreeContainersInStep pins the rebuild's
// three resets. when, order and entries must describe the same set after every
// seed: if order falls short of when, evictLocked reaches Back() on an empty
// list and nil-panics on the connection path, and entries grows without bound.
// Seeding once into a fresh map cannot see this — it takes successive seeds of
// disjoint content.
func TestLastSeen_RepeatedSeedsKeepTheThreeContainersInStep(t *testing.T) {
	base := time.Date(2026, 8, 19, 0, 0, 0, 0, time.UTC)
	generation := func(round int) *drift.Baseline {
		entries := make([]decisionlog.Entry, 150)
		for i := range entries {
			entries[i] = decisionlog.Entry{
				Timestamp: base.Add(time.Duration(round*1000+i) * time.Second).Format(time.RFC3339),
				Decision:  decisionlog.DecisionAllow, Exe: "/usr/bin/curl",
				Host: "gen" + strconv.Itoa(round) + "-" + strconv.Itoa(i) + ".example",
			}
		}
		return drift.BuildBaseline(&catalog.Catalog{}, entries)
	}

	l := newLastSeen(100)
	for round := 0; round < 5; round++ {
		l.seed(generation(round))
		l.advance("hot-pair", base.Add(time.Duration(round)*time.Hour))
		l.mu.Lock()
		when, order, entries := len(l.when), l.order.Len(), len(l.entries)
		l.mu.Unlock()
		if when != order || when != entries {
			t.Fatalf("round %d: when=%d order=%d entries=%d; the rebuild left them out of step", round, when, order, entries)
		}
		if when > 100 {
			t.Fatalf("round %d: retained %d pairs, over the 100 cap", round, when)
		}
	}
}

func TestLastSeen_SeedCountsOnlyLiveReferencesItDropped(t *testing.T) {
	b, base := overCapacityBaseline(t, 6000)

	// A live pair the snapshot does not contain, recent enough to survive. The
	// pair the cap displaces is therefore a historical one that was never live.
	l := newLastSeen(maxLiveLastSeenPairs)
	l.advance("live-only-pair", base.Add(10*time.Hour))
	evicted, overCap := l.seed(b)
	if overCap == 0 {
		t.Fatal("a 6000-pair baseline must report cap pressure against a 4096-pair cap")
	}
	if evicted != 0 {
		t.Errorf("seed reported %d live reference(s) dropped, but the pairs it declined were historical and never held", evicted)
	}
	if l.at("live-only-pair").IsZero() {
		t.Error("the live-only pair was dropped despite holding the newest reference")
	}

	// And the counter must still move when a live reference really is lost:
	// a snapshot of entirely newer pairs displaces everything held before it.
	newer := make([]decisionlog.Entry, maxLiveLastSeenPairs)
	for i := range newer {
		newer[i] = decisionlog.Entry{
			Timestamp: base.Add(100*time.Hour + time.Duration(i)*time.Second).Format(time.RFC3339),
			Decision:  decisionlog.DecisionAllow, Exe: "/usr/bin/curl",
			Host: "fresh-" + strconv.Itoa(i) + ".example",
		}
	}
	displaced, _ := l.seed(drift.BuildBaseline(&catalog.Catalog{}, newer))
	if displaced == 0 {
		t.Error("a snapshot of entirely newer pairs displaced live references but reported none")
	}
}

// pairKey names the live key for one host in overCapacityBaseline's fixture.
func pairKey(base time.Time, i int) string {
	return drift.BaselinePairKey(decisionlog.Entry{
		Timestamp: base.Add(time.Duration(i) * time.Second).Format(time.RFC3339),
		Decision:  decisionlog.DecisionAllow, Exe: "/usr/bin/curl",
		Host: "host-" + strconv.Itoa(i) + ".example",
	})
}

// TestLastSeen_SeedLeavesTheOldestPairNextToEvict pins the direction of seed's
// rebuild. Both the code comment and ScoreAgainst's doc assert that the newest
// reference ends up at the front and the oldest is what eviction reaches for
// next; without this, reversing the push loop makes the very next advance
// evict the NEWEST pair, and nothing notices.
func TestLastSeen_SeedLeavesTheOldestPairNextToEvict(t *testing.T) {
	b, base := overCapacityBaseline(t, 4)
	l := newLastSeen(4)
	l.seed(b)
	l.advance("brand-new-pair", base.Add(time.Hour))

	if got := l.at(pairKey(base, 0)); !got.IsZero() {
		t.Errorf("oldest seeded pair survived the first eviction: %v", got)
	}
	if got := l.at(pairKey(base, 3)); got.IsZero() {
		t.Error("newest seeded pair was evicted first; the rebuilt list is ordered backwards")
	}
}

// TestLastSeen_SeedBreaksTimestampTiesDeterministically covers the case the
// sort's tie-break exists for. Decision-log timestamps are second-resolution,
// so ties at the cap boundary are ordinary; without the tie-break, which pair
// survives falls back to map iteration order and re-rolls every refresh.
func TestLastSeen_SeedBreaksTimestampTiesDeterministically(t *testing.T) {
	base := time.Date(2026, 8, 19, 0, 0, 0, 0, time.UTC)
	entries := []decisionlog.Entry{{
		Timestamp: base.Add(time.Hour).Format(time.RFC3339), Decision: decisionlog.DecisionAllow,
		Exe: "/usr/bin/curl", Host: "newest.example",
	}}
	for i := 0; i < 20; i++ { // all sharing one timestamp, at the boundary
		entries = append(entries, decisionlog.Entry{
			Timestamp: base.Format(time.RFC3339), Decision: decisionlog.DecisionAllow,
			Exe: "/usr/bin/curl", Host: "tied-" + strconv.Itoa(i) + ".example",
		})
	}
	b := drift.BuildBaseline(&catalog.Catalog{}, entries)

	retained := func() []string {
		l := newLastSeen(5)
		l.seed(b)
		l.mu.Lock()
		defer l.mu.Unlock()
		out := make([]string, 0, len(l.when))
		for k := range l.when {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	first := retained()
	for attempt := 0; attempt < 8; attempt++ {
		got := retained()
		if !reflect.DeepEqual(first, got) {
			t.Fatalf("tied pairs retained a different set on attempt %d:\n  %v\n  %v", attempt, first, got)
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

	// A seed that displaces live references must count them too. SetBaseline
	// reports its own per-refresh figure, so nothing in production reads this
	// counter — without this assertion the accumulation is deletable.
	b, base2 := overCapacityBaseline(t, 8)
	seeded := newLastSeen(2)
	seeded.advance(pairKey(base2, 0), base2)
	seeded.advance(pairKey(base2, 1), base2.Add(time.Second))
	before := seeded.evictionCount()
	seeded.seed(b)
	if seeded.evictionCount() <= before {
		t.Errorf("evictionCount = %d after a seed that displaced live references, was %d; seed-driven evictions are not counted",
			seeded.evictionCount(), before)
	}
}

// TestLastSeen_SeedSkipsPairsWithNoRecordedTime covers the zero-time guard.
// clouds.add writes a pair's meta and points before parsing its timestamp and
// returns early when that fails, so a malformed decision-log line leaves a pair
// that Pairs lists with no LastSeenFor. Admitting it would put a zero reference
// in the live map and inflate the operator-facing cap-pressure count.
func TestLastSeen_SeedSkipsPairsWithNoRecordedTime(t *testing.T) {
	base := time.Date(2026, 8, 19, 0, 0, 0, 0, time.UTC)
	good := decisionlog.Entry{
		Timestamp: base.Format(time.RFC3339), Decision: decisionlog.DecisionAllow,
		Exe: "/usr/bin/curl", Host: "good.example",
	}
	malformed := decisionlog.Entry{
		Timestamp: "not-a-timestamp", Decision: decisionlog.DecisionAllow,
		Exe: "/usr/bin/curl", Host: "malformed.example",
	}
	b := drift.BuildBaseline(&catalog.Catalog{}, []decisionlog.Entry{good, malformed})

	var listed bool
	for _, pair := range b.Pairs() {
		if pair.Host == "malformed.example" {
			listed = true
			if !b.LastSeenFor(pair.Identity, pair.Host).IsZero() {
				t.Skip("malformed entries no longer produce a pair without a recorded time")
			}
		}
	}
	if !listed {
		t.Skip("malformed entries no longer produce a listed pair")
	}

	l := newLastSeen(maxLiveLastSeenPairs)
	l.seed(b)
	if got := l.at(drift.BaselinePairKey(malformed)); !got.IsZero() {
		t.Errorf("a pair with no recorded time entered the live map as %v", got)
	}
	if l.seedLockedPairs != 1 {
		t.Errorf("seed carried %d pairs into the locked section, want 1: the timeless pair must not be counted", l.seedLockedPairs)
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
