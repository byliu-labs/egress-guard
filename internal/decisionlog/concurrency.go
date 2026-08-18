package decisionlog

import (
	"sort"
	"time"
)

// ConcurrencyIndex answers "how many connections were in flight at instant t"
// from log-derived connection timing. It is never persisted.
type ConcurrencyIndex struct {
	events   []concEvent
	instants []concInstant
}

type concEvent struct {
	at     time.Time
	delta  int
	connID string
}

type concInstant struct {
	at     time.Time
	connID string
}

// BuildConcurrencyIndex folds joined connections into an open/close timeline.
// A connection without a completed flow is an egress attempt only at its open
// instant; it is kept separately because a zero-width open/close pair cancels
// before a query can observe it.
func BuildConcurrencyIndex(js []Joined) *ConcurrencyIndex {
	idx := &ConcurrencyIndex{}
	for _, j := range js {
		open, err := time.Parse(time.RFC3339, j.Decision.Timestamp)
		if err != nil {
			continue
		}
		if !j.HasFlow || j.Flow.DurationMS <= 0 {
			idx.instants = append(idx.instants, concInstant{at: open, connID: j.Decision.ConnID})
			continue
		}
		shut := open.Add(time.Duration(j.Flow.DurationMS) * time.Millisecond)
		idx.events = append(idx.events,
			concEvent{at: open, delta: 1, connID: j.Decision.ConnID},
			concEvent{at: shut, delta: -1, connID: j.Decision.ConnID})
	}
	sort.Slice(idx.events, func(a, b int) bool {
		if idx.events[a].at.Equal(idx.events[b].at) {
			return idx.events[a].delta > idx.events[b].delta
		}
		return idx.events[a].at.Before(idx.events[b].at)
	})
	return idx
}

// At returns the count at t without the subject connection. Excluding the
// subject answers what else was egressing rather than adding a constant self.
func (idx *ConcurrencyIndex) At(t time.Time, excludeConnID string) int {
	if idx == nil {
		return 0
	}
	hi := sort.Search(len(idx.events), func(i int) bool {
		return idx.events[i].at.After(t)
	})
	n := 0
	for _, event := range idx.events[:hi] {
		if event.connID != "" && event.connID == excludeConnID {
			continue
		}
		n += event.delta
	}
	for _, instant := range idx.instants {
		if instant.at.Equal(t) && (instant.connID == "" || instant.connID != excludeConnID) {
			n++
		}
	}
	if n < 0 {
		return 0
	}
	return n
}
