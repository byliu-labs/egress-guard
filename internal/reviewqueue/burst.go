package reviewqueue

import "time"

// DefaultBurstThreshold is the distinct-UUID count that flags careful review.
const DefaultBurstThreshold = 5

// DefaultBurstWindow is the lookback DetectBursts scans.
const DefaultBurstWindow = 24 * time.Hour

// DetectBursts marks candidates with many distinct UUIDs in a recent window.
func (q *Queue) DetectBursts(threshold int, window time.Duration) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, c := range q.candidates {
		c.Burst = distinctUUIDsInWindow(c.events, window) >= threshold
	}
}

func distinctUUIDsInWindow(events []uuidEvent, window time.Duration) int {
	if len(events) == 0 {
		return 0
	}
	latest := events[0].Seen
	for _, e := range events {
		if e.Seen.After(latest) {
			latest = e.Seen
		}
	}
	cutoff := latest.Add(-window)
	seen := make(map[string]bool, len(events))
	for _, e := range events {
		if e.Seen.Before(cutoff) {
			continue
		}
		seen[e.UUID] = true
	}
	return len(seen)
}
