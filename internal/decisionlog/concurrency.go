package decisionlog

import (
	"sort"
	"time"
)

// ConcurrencyIndex answers "how many connections were in flight at instant t"
// from log-derived connection timing. It is never persisted.
type ConcurrencyIndex struct {
	events   []concEvent
	prefix   []int             // prefix[i] is the count after events[:i].
	own      map[string][2]int // connID -> open and close event indices.
	instants map[int64]instantCounts
}

type concEvent struct {
	at     time.Time
	delta  int
	connID string
}

type instantCounts struct {
	total    int
	byConnID map[string]int
}

// BuildConcurrencyIndex folds joined connections into an open/close timeline.
// A connection without a completed flow is an egress attempt only at its open
// instant; it is kept separately because a zero-width open/close pair cancels
// before a query can observe it.
func BuildConcurrencyIndex(js []Joined) *ConcurrencyIndex {
	idx := &ConcurrencyIndex{instants: make(map[int64]instantCounts)}
	for _, j := range js {
		open, err := time.Parse(time.RFC3339, j.Decision.Timestamp)
		if err != nil {
			continue
		}
		if !j.HasFlow || j.Flow.DurationMS <= 0 {
			at := open.UnixNano()
			counts, ok := idx.instants[at]
			if !ok {
				counts.byConnID = make(map[string]int)
			}
			counts.total++
			counts.byConnID[j.Decision.ConnID]++
			idx.instants[at] = counts
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
	idx.prefix = make([]int, len(idx.events)+1)
	idx.own = make(map[string][2]int, len(idx.events)/2)
	for i, event := range idx.events {
		idx.prefix[i+1] = idx.prefix[i] + event.delta
		if event.connID == "" {
			continue
		}
		own, ok := idx.own[event.connID]
		if !ok {
			own = [2]int{-1, -1}
		}
		if event.delta > 0 {
			own[0] = i
		} else {
			own[1] = i
		}
		idx.own[event.connID] = own
	}
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
	n := idx.prefix[hi]
	if excludeConnID != "" {
		if own, ok := idx.own[excludeConnID]; ok {
			if own[0] >= 0 && own[0] < hi {
				n--
			}
			if own[1] >= 0 && own[1] < hi {
				n++
			}
		}
	}
	if instants, ok := idx.instants[t.UnixNano()]; ok {
		n += instants.total
		if excludeConnID != "" {
			n -= instants.byConnID[excludeConnID]
		}
	}
	if n < 0 {
		return 0
	}
	return n
}
