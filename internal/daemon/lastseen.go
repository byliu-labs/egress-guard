package daemon

import (
	"sync"
	"time"

	"github.com/byliu-labs/egress-guard/internal/decisionlog"
	"github.com/byliu-labs/egress-guard/internal/drift"
)

const maxLiveLastSeenPairs = 4096

// lastSeen is the daemon's live answer to when a pair last connected. It keeps
// scoring in the same walk-forward space used to build the baseline clouds.
type lastSeen struct {
	mu   sync.Mutex
	max  int
	when map[string]time.Time
}

func newLastSeen(max int) *lastSeen {
	if max < 1 {
		max = 1
	}
	return &lastSeen{max: max, when: make(map[string]time.Time)}
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
		var oldestKey string
		var oldest time.Time
		for key, at := range l.when {
			if oldestKey == "" || at.Before(oldest) {
				oldestKey, oldest = key, at
			}
		}
		delete(l.when, oldestKey)
	}
}

// seed folds a rebuilt snapshot into the live state without moving a live
// reference backwards when the log snapshot lags a served connection.
func (l *lastSeen) seed(b *drift.Baseline) {
	if b == nil {
		return
	}
	for _, pair := range b.Pairs() {
		at := b.LastSeenFor(pair.Identity, pair.Host)
		if at.IsZero() {
			continue
		}
		l.advance(drift.BaselinePairKeyFor(pair.Identity, pair.Host), at)
	}
}
