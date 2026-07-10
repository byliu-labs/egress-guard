// Package reviewqueue is the maintainer-facing gate between telemetry reports
// and the public baseline catalog.
package reviewqueue

import (
	"sort"
	"sync"
	"time"

	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/telemetry"
)

// Status is a candidate's place in the maintainer workflow.
type Status string

const (
	StatusQueued   Status = "queued"
	StatusApproved Status = "approved"
	StatusRejected Status = "rejected"
)

// Key identifies one review queue row.
type Key struct {
	Identity catalog.Identity
	Host     string
	Verdict  string
}

type uuidEvent struct {
	UUID string
	Seen time.Time
}

// Candidate is one review queue row.
type Candidate struct {
	Key        Key
	Count      int
	FirstSeen  time.Time
	LastSeen   time.Time
	Burst      bool
	Evidence   string
	Confidence catalog.Confidence
	Status     Status

	events []uuidEvent
}

// DistinctUUIDs returns the number of different installs that reported this row.
func (c Candidate) DistinctUUIDs() int {
	seen := make(map[string]bool, len(c.events))
	for _, e := range c.events {
		seen[e.UUID] = true
	}
	return len(seen)
}

// Queue is the in-memory maintainer review queue.
type Queue struct {
	mu             sync.Mutex
	candidates     map[Key]*Candidate
	store          *store
	corruptRecords int
}

// New returns an empty in-memory Queue.
func New() *Queue {
	return &Queue{candidates: make(map[Key]*Candidate)}
}

// CorruptRecords returns how many JSONL records Open skipped during replay.
func (q *Queue) CorruptRecords() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.corruptRecords
}

// Ingest folds one telemetry.Report into the queue. It never promotes.
func (q *Queue) Ingest(r telemetry.Report) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.ingestLocked(r, time.Now(), true)
}

func (q *Queue) ingestLocked(r telemetry.Report, now time.Time, persist bool) error {
	key := Key{Identity: r.Identity, Host: r.Host, Verdict: r.Verdict}
	c, ok := q.candidates[key]
	if !ok {
		c = &Candidate{Key: key, FirstSeen: now, Status: StatusQueued}
		q.candidates[key] = c
	}
	c.Count++
	c.LastSeen = now
	c.events = append(c.events, uuidEvent{UUID: r.InstallUUID, Seen: now})
	if persist && q.store != nil {
		return q.store.append(record{Kind: kindReport, Timestamp: now, Report: &r})
	}
	return nil
}

// Candidates returns rows ordered by frequency descending, then oldest first.
func (q *Queue) Candidates() []Candidate {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([]Candidate, 0, len(q.candidates))
	for _, c := range q.candidates {
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].FirstSeen.Before(out[j].FirstSeen)
	})
	return out
}
