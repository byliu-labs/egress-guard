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

// evictionCount is the lifetime number of pairs dropped for capacity. Callers
// that want "what did this seed cost" must difference it themselves: reporting
// the running total as if it were a per-seed figure turns one steady-state
// condition into an alarm whose number only ever grows.
func (l *lastSeen) evictionCount() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.evictions
}

// seed folds a rebuilt snapshot into the live state without moving a live
// reference backwards when the log snapshot lags a served connection.
//
// It rebuilds rather than inserting pair-by-pair. Incremental insertion cannot
// work here: Baseline.Pairs ranges a map, so it yields a different order every
// call, and advance treats every insert as recent activity — so feeding a
// snapshot through it would make the surviving set a fresh coin flip per
// refresh, and would push out the pair a connection goroutine advanced seconds
// ago in favour of historical ones. Rebuilding keeps the invariant the
// daemon/replay agreement is written against: the pairs retained are the ones
// with the newest references, live or historical, and reseeding the same
// snapshot is a no-op. One sort per hour is not a cost worth optimising.
func (l *lastSeen) seed(b *drift.Baseline) {
	if b == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	merged := make(map[string]time.Time, len(l.when))
	for key, at := range l.when {
		merged[key] = at
	}
	for _, pair := range b.Pairs() {
		at := b.LastSeenFor(pair.Identity, pair.Host)
		if at.IsZero() {
			continue
		}
		key := drift.BaselinePairKeyFor(pair.Identity, pair.Host)
		if live, ok := merged[key]; ok && !at.After(live) {
			continue
		}
		merged[key] = at
	}

	keys := make([]string, 0, len(merged))
	for key := range merged {
		keys = append(keys, key)
	}
	// Newest first; ties broken by key so retention never depends on map order.
	sort.Slice(keys, func(i, j int) bool {
		if merged[keys[i]].Equal(merged[keys[j]]) {
			return keys[i] < keys[j]
		}
		return merged[keys[i]].After(merged[keys[j]])
	})
	if len(keys) > l.max {
		l.evictions += uint64(len(keys) - l.max)
		keys = keys[:l.max]
	}

	l.when = make(map[string]time.Time, len(keys))
	l.entries = make(map[string]*list.Element, len(keys))
	l.order = list.New()
	// Push oldest-first so the newest reference ends up at the front and the
	// oldest is what eviction reaches for next.
	for i := len(keys) - 1; i >= 0; i-- {
		l.when[keys[i]] = merged[keys[i]]
		l.entries[keys[i]] = l.order.PushFront(keys[i])
	}
}
