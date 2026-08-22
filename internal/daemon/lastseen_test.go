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

// TestReduceSnapshot_CutsToTheCap pins the reduction itself, on the pure
// function, with no lock and no goroutines in the picture.
func TestReduceSnapshot_CutsToTheCap(t *testing.T) {
	for _, pairs := range []int{2 * maxLiveLastSeenPairs, 25 * maxLiveLastSeenPairs} {
		b, _ := overCapacityBaseline(t, pairs)
		candidates, overCap := reduceSnapshot(b, maxLiveLastSeenPairs)
		if len(candidates) != maxLiveLastSeenPairs {
			t.Errorf("a %d-pair snapshot reduced to %d, want the %d-pair cap", pairs, len(candidates), maxLiveLastSeenPairs)
		}
		if want := pairs - maxLiveLastSeenPairs; overCap != want {
			t.Errorf("a %d-pair snapshot reported overCap = %d, want %d", pairs, overCap, want)
		}
	}
	// A snapshot below the cap is bounded by its own size, not padded to it.
	small, _ := overCapacityBaseline(t, 64)
	candidates, overCap := reduceSnapshot(small, maxLiveLastSeenPairs)
	if len(candidates) != 64 || overCap != 0 {
		t.Errorf("64-pair snapshot reduced to %d with overCap %d, want 64 and 0", len(candidates), overCap)
	}
}

// TestLastSeen_SeedReducesTheSnapshotBeforeTakingTheLock pins WHERE the
// expensive work happens, which is the property that matters and the one a
// value assertion cannot reach. at() sits inline on connection setup, and the
// baseline carries one pair per distinct (identity, host) the machine has ever
// logged, so a locked section that scales with history stalls every new TLS
// connection — measured at 167ms for 100k pairs.
//
// An earlier version of this test asserted a count that seed itself recorded.
// That is production reporting a number about its own behaviour: the value is
// invariant to where the lock is taken, so moving the lock to the top of seed
// left it green. This holds the mutex from the test — standing in for a
// connection goroutine parked in at() — and requires the reduction to complete
// anyway. With the lock taken first the hook can never fire, so the timeout is
// deterministic rather than a performance bound.
func TestLastSeen_SeedReducesTheSnapshotBeforeTakingTheLock(t *testing.T) {
	b, _ := overCapacityBaseline(t, 25*maxLiveLastSeenPairs)
	l := newLastSeen(maxLiveLastSeenPairs)

	reached := make(chan int, 1)
	t.Cleanup(func() { seedReduced = nil })
	seedReduced = func(n int) { reached <- n }

	l.mu.Lock()
	done := make(chan struct{})
	go func() { defer close(done); l.seed(b) }()

	var got int
	var timedOut bool
	select {
	case got = <-reached:
	case <-time.After(30 * time.Second):
		timedOut = true
	}
	l.mu.Unlock()
	<-done

	if timedOut {
		t.Fatalf("seed did not finish reducing a %d-pair snapshot while a connection goroutine held the lock: the sort now runs with every new TLS connection blocked in at()",
			25*maxLiveLastSeenPairs)
	}
	if got != maxLiveLastSeenPairs {
		t.Fatalf("seed carried %d pairs into the locked section, want at most the %d-pair cap", got, maxLiveLastSeenPairs)
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

// TestLastSeen_SeedRetainsExactlyTheNewestMaxOfTheMergedSet pins the identity
// of the surviving set, which is what the daemon/replay agreement is written
// against: "the pairs it keeps are the most recently active ones — the same set
// replay still holds."
//
// Asserting that one designated pair survived cannot do this. With 4096 of 4097
// pairs retained, an unordered rebuild keeps any given pair 99.98% of the time,
// so that assertion passes almost always against a merge with no sort at all.
// The expected set here is computed from the full snapshot merged by hand, not
// from the reduced candidate slice, so both sides of the comparison do not flow
// through the same production code.
func TestLastSeen_SeedRetainsExactlyTheNewestMaxOfTheMergedSet(t *testing.T) {
	const (
		max      = 64
		snapshot = 100
		liveOnly = 10
	)
	b, base := overCapacityBaseline(t, snapshot)

	l := newLastSeen(max)
	oracle := map[string]time.Time{}
	for i := 0; i < snapshot; i++ {
		oracle[pairKey(base, i)] = base.Add(time.Duration(i) * time.Second)
	}
	for j := 0; j < liveOnly; j++ {
		key, at := "live-"+strconv.Itoa(j), base.Add(time.Duration(200+j)*time.Second)
		l.advance(key, at)
		oracle[key] = at
	}
	// One key held by both sides, live strictly newer: the merge must keep the
	// live time, so this pair ranks first rather than last.
	shared := pairKey(base, 0)
	sharedAt := base.Add(300 * time.Second)
	l.advance(shared, sharedAt)
	oracle[shared] = sharedAt

	// And one the other way round — snapshot strictly newer than the live
	// entry, so the merge must take the SNAPSHOT's time. Every other fixture in
	// this package has live newer than snapshot, leaving half of
	// merged[k] = max(live, candidate) unasserted. Reachable whenever the log
	// outruns the live map for a pair: a restored or imported log, or a
	// backward clock adjustment.
	staleLive := pairKey(base, 99)
	l.advance(staleLive, base.Add(-time.Hour))
	// oracle[staleLive] stays the snapshot's time, set in the loop above.

	l.seed(b)

	expected := make([]keyedTime, 0, len(oracle))
	for key, at := range oracle {
		expected = append(expected, keyedTime{key, at})
	}
	// Ranked by a comparator written HERE, not by production's newestFirst.
	// Ranking both sides with the same predicate makes this test invariant to
	// any change in it — including a full inversion — which is precisely what
	// a test claiming to pin "the identity of the surviving set" must not be.
	sort.Slice(expected, func(i, j int) bool {
		if expected[i].at.Equal(expected[j].at) {
			return expected[i].key < expected[j].key
		}
		return expected[i].at.After(expected[j].at)
	})
	want := map[string]time.Time{}
	for _, e := range expected[:max] {
		want[e.key] = e.at
	}

	l.mu.Lock()
	got := make(map[string]time.Time, len(l.when))
	for key, at := range l.when {
		got[key] = at
	}
	l.mu.Unlock()

	if !reflect.DeepEqual(got, want) {
		var missing, extra []string
		for key := range want {
			if _, ok := got[key]; !ok {
				missing = append(missing, key)
			}
		}
		for key := range got {
			if _, ok := want[key]; !ok {
				extra = append(extra, key)
			}
		}
		sort.Strings(missing)
		sort.Strings(extra)
		t.Fatalf("retained set is not the newest %d of the merged set\n  kept %d, want %d\n  missing (%d): %v\n  unexpected (%d): %v",
			max, len(got), len(want), len(missing), missing, len(extra), extra)
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

	// Assert the WHOLE rebuilt order, not two endpoints of it. Go yields only a
	// handful of rotations for a map this small, so probing the front and back
	// leaves an unordered rebuild passing about one run in three — which is how
	// a regression here reaches CI green, then lives on as an intermittent that
	// gets rerun until it goes away.
	l.mu.Lock()
	var order []string
	for element := l.order.Front(); element != nil; element = element.Next() {
		order = append(order, element.Value.(string))
	}
	l.mu.Unlock()
	want := []string{pairKey(base, 3), pairKey(base, 2), pairKey(base, 1), pairKey(base, 0)}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("rebuilt LRU order = %v, want newest-first %v", order, want)
	}

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

	// Determinism alone does not pin the tie-break: reversing it is equally
	// deterministic, so the loop above passes against `a.key > b.key`. Name the
	// survivors. Cap 5 = the newest pair plus the four lexicographically first
	// of the twenty tied ones, which under a reversed comparator would be
	// tied-9, -8, -7, -6 instead.
	want := []string{
		drift.BaselinePairKeyFor(catalog.Identity{ExeBasename: "curl"}, "newest.example"),
		drift.BaselinePairKeyFor(catalog.Identity{ExeBasename: "curl"}, "tied-0.example"),
		drift.BaselinePairKeyFor(catalog.Identity{ExeBasename: "curl"}, "tied-1.example"),
		drift.BaselinePairKeyFor(catalog.Identity{ExeBasename: "curl"}, "tied-10.example"),
		drift.BaselinePairKeyFor(catalog.Identity{ExeBasename: "curl"}, "tied-11.example"),
	}
	sort.Strings(want)
	if !reflect.DeepEqual(first, want) {
		t.Fatalf("tied pairs retained\n  %v\nwant the lexicographically first four plus the newest\n  %v", first, want)
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
	// The timeless pair must not count as cap pressure either. With a cap of
	// one and one real pair, measuring overCap on the raw pair list instead of
	// on the dated candidates reports pressure on a map that fits exactly.
	if candidates, overCap := reduceSnapshot(b, 1); len(candidates) != 1 || overCap != 0 {
		t.Errorf("reduceSnapshot kept %d candidate(s) with overCap %d, want 1 and 0: a pair with no recorded time is neither a candidate nor cap pressure",
			len(candidates), overCap)
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

// TestLastSeen_DivergesFromReplayOnOutOfOrderCompletion pins the second bound
// named in ScoreAgainst's doc comment. An entry is stamped when its branch
// decides but written only after the upstream dial returns, so two overlapping
// connections to one pair can reach the log in dial-completion order rather
// than timestamp order. The daemon's advance is monotonic and keeps the newer
// reference; BuildBaseline assigns unconditionally and keeps whichever line
// came last in the file. They disagree, and the doc comment says so.
//
// This asserts a divergence rather than an agreement on purpose. The comment
// previously claimed these two agreed for exactly this case; without a test the
// claim was free to be wrong, and a later change that closed the gap would be
// just as invisible. Either direction now has to update this test.
func TestLastSeen_DivergesFromReplayOnOutOfOrderCompletion(t *testing.T) {
	stampedFirst := decisionlog.Entry{
		Timestamp: "2026-08-19T12:00:00Z", Decision: decisionlog.DecisionAllow,
		Exe: "/usr/bin/curl", Host: "overlap.example",
	}
	stampedSecond := decisionlog.Entry{
		Timestamp: "2026-08-19T12:00:01Z", Decision: decisionlog.DecisionAllow,
		Exe: "/usr/bin/curl", Host: "overlap.example",
	}
	key := drift.BaselinePairKey(stampedFirst)
	if key != drift.BaselinePairKey(stampedSecond) {
		t.Fatal("fixture is wrong: both connections must belong to one pair")
	}

	// File order is dial-completion order: the connection stamped first dialed
	// slowly, so it is written second.
	logOrder := []decisionlog.Entry{stampedSecond, stampedFirst}

	l := newLastSeen(maxLiveLastSeenPairs)
	for _, entry := range logOrder {
		l.advanceEntry(entry)
	}
	daemon := l.at(key)

	b := drift.BuildBaseline(&catalog.Catalog{}, logOrder)
	replay := b.LastSeenFor(catalog.Identity{ExeBasename: "curl"}, "overlap.example")

	if daemon.IsZero() || replay.IsZero() {
		t.Fatalf("fixture is wrong: daemon = %v, replay = %v, both must be set", daemon, replay)
	}
	if !daemon.After(replay) {
		t.Fatalf("daemon = %v, replay = %v: the daemon must keep the newer reference and replay the last-written one. "+
			"If replay became monotonic, ScoreAgainst's doc comment now overstates the bound and must be updated with this test.",
			daemon, replay)
	}
}

// TestLastSeen_SeedWithNothingToFoldInTakesNoLock pins the empty case out of
// the locked section. Before seed was split, a nil baseline returned before the
// lock; the split moved that check into reduceSnapshot, after which seed took
// the lock and ran a full rebuild against an empty candidate slice — ~1.6ms of
// pure waste per call with every new TLS connection blocked in at(), in the
// function whose doc says the stall cannot be reintroduced by moving one line.
//
// The waste is the smaller half. mergeLocked rebuilds the LRU list in timestamp
// order, so a refresh that folds in nothing still reorders advance-recency into
// timestamp order and changes which pair the next eviction takes.
func TestLastSeen_SeedWithNothingToFoldInTakesNoLock(t *testing.T) {
	l := newLastSeen(2)
	base := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	// Advance the later-stamped pair FIRST, so recency order and timestamp
	// order disagree. advance is monotonic per key, so re-advancing one pair
	// cannot produce this — it takes two keys moving against their clocks.
	l.advance("stamped-later", base.Add(time.Hour))
	l.advance("stamped-earlier", base)
	// By recency "stamped-later" is now at the back and is next to evict. A
	// rebuild would reorder by timestamp and put "stamped-earlier" there.

	done := make(chan struct{})
	l.mu.Lock()
	go func() {
		defer close(done)
		l.seed(nil)
		l.seed(drift.BuildBaseline(&catalog.Catalog{}, nil))
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		l.mu.Unlock()
		t.Fatal("seed blocked on the lock with nothing to fold in: the empty case now rebuilds all three containers while connection goroutines wait in at()")
	}
	l.mu.Unlock()

	// And it must report no cap pressure. This is the daemon's boot path when
	// the decision log will not parse: loadOrBuildBaseline returns nil, New
	// hands that to SetBaseline with the real logger already live, so a garbage
	// overCap here becomes an alarm printed at startup on exactly the machine
	// whose log is already broken.
	if evicted, overCap := l.seed(nil); evicted != 0 || overCap != 0 {
		t.Errorf("seed(nil) returned evicted=%d overCap=%d, want 0 and 0", evicted, overCap)
	}

	l.advance("brand-new", base.Add(2*time.Hour))
	if l.at("stamped-earlier").IsZero() {
		t.Error("a seed with nothing to fold in reordered the list into timestamp order: the most-recently-advanced pair was evicted instead of the least-recently-advanced one")
	}
	if !l.at("stamped-later").IsZero() {
		t.Error("the least-recently-advanced pair survived eviction; the list is no longer in recency order")
	}
}

// TestLastSeen_MergeLockedBoundsAnUnreducedSnapshot pins the cost boundary,
// which no assertion about the retained set can reach: the reduction is sound,
// so merging the full snapshot yields an identical retained set and only the
// latency differs.
//
// It asserts truncation-and-count rather than a panic. Crashing here would take
// a boot-resident daemon offline while its pf anchor still redirects 443 — a
// total-egress outage that repeats on every restart — as the response to a
// latency regression. The counter keeps the mechanical catch without that tail.
func TestLastSeen_MergeLockedBoundsAnUnreducedSnapshot(t *testing.T) {
	l := newLastSeen(4)
	oversized := make([]keyedTime, 9)
	base := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	for i := range oversized {
		oversized[i] = keyedTime{"pair-" + strconv.Itoa(i), base.Add(time.Duration(i) * time.Second)}
	}

	l.mu.Lock()
	l.mergeLocked(oversized)
	held := len(l.when)
	l.mu.Unlock()

	if held != 4 {
		t.Errorf("live map holds %d pairs after an oversized merge, want the %d-pair cap", held, 4)
	}
	if got := l.mergeOverflowCount(); got != 5 {
		t.Errorf("mergeOverflowCount = %d, want 5: the overflow must be counted, or an unreduced snapshot reaches the lock silently", got)
	}
}

// TestLastSeen_SeedNeverOverflowsTheLockedMerge is the half that catches a real
// regression. The test above proves mergeLocked copes when handed too much;
// this proves seed never hands it too much. Without it, reducing one slice and
// passing a different one to mergeLocked is invisible — the retained set is
// identical either way.
func TestLastSeen_SeedNeverOverflowsTheLockedMerge(t *testing.T) {
	b, _ := overCapacityBaseline(t, 25*maxLiveLastSeenPairs)
	l := newLastSeen(maxLiveLastSeenPairs)
	l.seed(b)
	if got := l.mergeOverflowCount(); got != 0 {
		t.Fatalf("mergeOverflowCount = %d after a normal seed, want 0: %d pairs crossed into the locked section unreduced, stalling every new TLS connection behind the refresh",
			got, got)
	}
}

// TestLastSeen_AdvanceAtAnEqualTimeDoesNotRefront pins advance's equality
// boundary. TestLastSeen_AdvanceIsMonotonic only ever supplies a strictly
// earlier timestamp, so it cannot tell `!at.After(previous)` from
// `at.Before(previous)` — the two differ only when the times are equal.
//
// Equal must NOT re-front. Decision-log timestamps are second-resolution, so
// two connections to one pair inside the same second are ordinary; treating the
// second as fresh activity lets a repeated or replayed entry rescue a pair from
// eviction and changes which pair the next eviction takes.
func TestLastSeen_AdvanceAtAnEqualTimeDoesNotRefront(t *testing.T) {
	l := newLastSeen(2)
	base := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	l.advance("first", base)
	l.advance("second", base.Add(time.Second))
	// "first" is now least-recently-advanced and next to evict.
	l.advance("first", base) // identical timestamp: must be a no-op
	l.advance("third", base.Add(2*time.Second))

	if !l.at("first").IsZero() {
		t.Error("re-advancing a pair at its existing timestamp rescued it from eviction; equal time is being treated as fresh activity")
	}
	if l.at("second").IsZero() {
		t.Error("the more recently advanced pair was evicted instead")
	}
}
