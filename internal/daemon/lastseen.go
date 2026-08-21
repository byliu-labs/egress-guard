package daemon

import (
	"container/list"
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
	// seedLockedPairs is how many snapshot pairs the most recent seed had in
	// hand when it took the lock. It is the bound on work done while
	// connection goroutines are blocked in at(), so it must stay within max
	// however far the decision-log history grows. Timing cannot assert this:
	// the stall is one event among a million samples, so it lives in the same
	// statistic as scheduler noise.
	seedLockedPairs int
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

// seed folds a rebuilt snapshot into the live state without moving a live
// reference backwards when the log snapshot lags a served connection. It
// returns the number of live references it had to drop, and how far the
// snapshot exceeds the live cap.
//
// It rebuilds rather than inserting pair-by-pair. Incremental insertion cannot
// work here: Baseline.Pairs ranges a map, so it yields a different order every
// call, and advance treats every insert as recent activity — so feeding a
// snapshot through it would make the surviving set a fresh coin flip per
// refresh, and would push out the pair a connection goroutine advanced seconds
// ago in favour of historical ones. Rebuilding keeps the invariant the
// daemon/replay agreement is written against: the pairs retained are the ones
// with the newest references, live or historical.
//
// The snapshot is reduced to its own newest max pairs BEFORE the lock is
// taken, and only that bounded slice is merged under it. This matters: the
// baseline has one pair per distinct (identity, host) ever logged and the
// daemon is boot-resident, so the snapshot grows without limit over the life
// of the machine — while at() sits inline on connection setup, immediately
// before the upstream dial. Sorting the whole history under the lock stalls
// every new TLS connection for as long as it takes (measured: 167ms at 100k
// pairs). The reduction is safe because a pair outside the snapshot's own top
// max can never survive the merge — live entries only add competitors for the
// same slots.
func (l *lastSeen) seed(b *drift.Baseline) (evicted, overCap int) {
	if b == nil {
		return 0, 0
	}
	// max is written once, in newLastSeen, and never again.
	max := l.max

	pairs := b.Pairs()
	candidates := make([]keyedTime, 0, len(pairs))
	for _, pair := range pairs {
		at := b.LastSeenFor(pair.Identity, pair.Host)
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

	l.mu.Lock()
	defer l.mu.Unlock()
	l.seedLockedPairs = len(candidates)

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
	if len(ordered) > max {
		for _, dropped := range ordered[max:] {
			if _, wasLive := l.when[dropped.key]; wasLive {
				evicted++
			}
		}
		l.evictions += uint64(evicted)
		ordered = ordered[:max]
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
	return evicted, overCap
}
