package daemon

import (
	"container/list"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/byliu-labs/egress-guard/internal/decisionlog"
	"github.com/byliu-labs/egress-guard/internal/drift"
)

const maxLiveLastSeenPairs = 4096

// lastSeen is the daemon's live answer to when a pair last connected. It keeps
// scoring in the same walk-forward space used to build the baseline clouds.
// When the live cap is reached, least-recently-advanced pairs are evicted.
type lastSeen struct {
	mu        sync.Mutex
	max       int
	when      map[string]time.Time
	order     *list.List
	entries   map[string]*list.Element
	evictions uint64
}

func newLastSeen(max int) *lastSeen {
	if max < 1 {
		max = 1
	}
	return &lastSeen{
		max:     max,
		when:    make(map[string]time.Time),
		order:   list.New(),
		entries: make(map[string]*list.Element),
	}
}

func (l *lastSeen) at(key string) time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.when[key]
}

// advance is monotonic because connections can complete out of order.
func (l *lastSeen) advance(key string, at time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if previous, ok := l.when[key]; ok && !at.After(previous) {
		return
	}
	l.when[key] = at
	if element, ok := l.entries[key]; ok {
		l.order.MoveToFront(element)
	} else {
		l.entries[key] = l.order.PushFront(key)
	}
	l.evictLocked()
}

// advanceEntry matches clouds.add: denials do not advance, while accepted
// decisions advance even when their flow is missing or unscorable.
func (l *lastSeen) advanceEntry(entry decisionlog.Entry) {
	if !drift.FoldsIntoBaseline(entry) {
		return
	}
	at, err := time.Parse(time.RFC3339, entry.Timestamp)
	if err != nil {
		return
	}
	l.advance(drift.BaselinePairKey(entry), at)
}

func (l *lastSeen) evictLocked() {
	for len(l.when) > l.max {
		element := l.order.Back()
		key := element.Value.(string)
		delete(l.when, key)
		delete(l.entries, key)
		l.order.Remove(element)
		l.evictions++
	}
}

// evictionCount is the lifetime number of LIVE references dropped for
// capacity — pairs this map actually held and then lost. It deliberately does
// not count historical pairs a seed declined to admit: those were never live,
// and folding them in here would report a stable, idempotent live set as
// though it were churning.
func (l *lastSeen) evictionCount() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.evictions
}

// keyedTime pairs a live key with its reference time so a snapshot can be
// ordered outside the lock.
type keyedTime struct {
	key string
	at  time.Time
}

// newestFirst is the retention order: most recent reference wins, ties broken
// by key so the result never depends on map iteration order.
func newestFirst(a, b keyedTime) bool {
	if a.at.Equal(b.at) {
		return a.key < b.key
	}
	return a.at.After(b.at)
}

// reduceSnapshot orders a rebuilt baseline newest-first and cuts it to the
// live cap, returning the retained candidates and how far the snapshot
// exceeded that cap.
//
// It is a package-level function taking no receiver and no lock, and that is
// the whole point of its existence. The baseline carries one pair per distinct
// (identity, host) ever logged and the daemon is boot-resident, so the snapshot
// grows without limit over the life of the machine — while at() sits inline on
// connection setup, immediately before the upstream dial. Sorting the whole
// history while holding the mutex stalls every new TLS connection for as long
// as it takes (measured: 167ms at 100k pairs). Keeping this work in a function
// that cannot reach l.mu means the stall cannot be reintroduced by moving one
// line; it would take moving this body into the locked section.
//
// The reduction is sound: a pair outside the snapshot's own top max can never
// survive the merge, because live entries only add competitors for the same
// slots, never remove them.
func reduceSnapshot(b *drift.Baseline, max int) (candidates []keyedTime, overCap int) {
	if b == nil {
		return nil, 0
	}
	pairs := b.Pairs()
	candidates = make([]keyedTime, 0, len(pairs))
	for _, pair := range pairs {
		at := b.LastSeenFor(pair.Identity, pair.Host)
		// A pair the log listed but never dated is not cap pressure: counting
		// it would inflate the operator-facing figure on a machine nowhere
		// near the cap. overCap is measured on candidates, never on pairs.
		if at.IsZero() {
			continue
		}
		candidates = append(candidates, keyedTime{drift.BaselinePairKeyFor(pair.Identity, pair.Host), at})
	}
	sort.Slice(candidates, func(i, j int) bool { return newestFirst(candidates[i], candidates[j]) })
	if overCap = len(candidates) - max; overCap < 0 {
		overCap = 0
	}
	if len(candidates) > max {
		candidates = candidates[:max]
	}
	return candidates, overCap
}

// seedReduced is a test seam fired with the reduced candidate count at the one
// instant that matters: after the snapshot has been cut down and before the
// mutex is taken. Nil in production. A test holding the lock can observe it
// fire, which is the only external evidence that the expensive work really
// happens outside the locked section — a value assertion cannot tell.
//
// It is an unsynchronised package-level var, which is safe only because no test
// in this package calls t.Parallel(). A parallel test that seeds would race the
// test that sets this; give it a mutex before adding one.
var seedReduced func(int)

// seed folds a rebuilt snapshot into the live state without moving a live
// reference backwards when the log snapshot lags a served connection. It
// returns the number of live references it had to drop, and how far the
// snapshot exceeds the live cap.
func (l *lastSeen) seed(b *drift.Baseline) (evicted, overCap int) {
	// max is written once, in newLastSeen, and never again — and is at least 1,
	// which is what makes the empty-candidate return below provably report no
	// cap pressure: overCap is computed before truncation, and truncating to
	// [:max] with max >= 1 cannot empty a non-empty slice.
	candidates, overCap := reduceSnapshot(b, l.max)
	if seedReduced != nil {
		seedReduced(len(candidates))
	}
	// Nothing to fold in, so do not take the lock at all. mergeLocked has no
	// empty case: it would copy the live map, sort it and rebuild all three
	// containers with connection goroutines blocked in at(), for no change to
	// the retained set. It is not even inert — the rebuild reorders the list
	// from advance-recency into timestamp order, so a no-op refresh would
	// change which pair the next eviction reaches for.
	if len(candidates) == 0 {
		return 0, overCap
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.mergeLocked(candidates), overCap
}

// mergeLocked folds an already-reduced snapshot into live state and rebuilds
// the three containers. It rebuilds rather than inserting pair-by-pair:
// Baseline.Pairs ranges a map, so it yields a different order every call, and
// advance treats every insert as recent activity — feeding a snapshot through
// it would make the surviving set a fresh coin flip per refresh, and would push
// out the pair a connection goroutine advanced seconds ago in favour of
// historical ones. Rebuilding keeps the invariant the daemon/replay agreement
// is written against: the pairs retained are the ones with the newest
// references, live or historical.
//
// Caller must hold l.mu, and candidates must already be bounded by l.max —
// enforced below rather than merely documented. The bound is the whole point of
// the split: an unreduced slice here means the full unbounded history is sorted
// and copied with connection goroutines blocked in at(), which is a stall that
// grows with the machine's lifetime and is invisible to every assertion about
// the retained set, because the reduction is sound and the retained set comes
// out identical either way. Only the cost differs, so only a check on the way
// in can catch it. A violation is a programming error, and this is a security
// daemon: crash rather than serve from a state we cannot reason about.
func (l *lastSeen) mergeLocked(candidates []keyedTime) (evicted int) {
	if len(candidates) > l.max {
		panic(fmt.Sprintf("daemon: mergeLocked given %d candidates against a %d-pair cap; reduceSnapshot must bound the snapshot before the lock is taken",
			len(candidates), l.max))
	}
	merged := make(map[string]time.Time, len(l.when)+len(candidates))
	for key, at := range l.when {
		merged[key] = at
	}
	for _, candidate := range candidates {
		if live, ok := merged[candidate.key]; ok && !candidate.at.After(live) {
			continue
		}
		merged[candidate.key] = candidate.at
	}

	ordered := make([]keyedTime, 0, len(merged))
	for key, at := range merged {
		ordered = append(ordered, keyedTime{key, at})
	}
	sort.Slice(ordered, func(i, j int) bool { return newestFirst(ordered[i], ordered[j]) })
	if len(ordered) > l.max {
		for _, dropped := range ordered[l.max:] {
			if _, wasLive := l.when[dropped.key]; wasLive {
				evicted++
			}
		}
		l.evictions += uint64(evicted)
		ordered = ordered[:l.max]
	}

	l.when = make(map[string]time.Time, len(ordered))
	l.entries = make(map[string]*list.Element, len(ordered))
	l.order = list.New()
	// Push oldest-first so the newest reference ends up at the front and the
	// oldest is what eviction reaches for next.
	for i := len(ordered) - 1; i >= 0; i-- {
		l.when[ordered[i].key] = ordered[i].at
		l.entries[ordered[i].key] = l.order.PushFront(ordered[i].key)
	}
	return evicted
}
