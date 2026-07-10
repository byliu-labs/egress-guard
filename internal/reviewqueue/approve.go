package reviewqueue

import (
	"fmt"
	"time"

	"github.com/byliu-labs/egress-guard/internal/catalog"
)

// SetEvidence attaches maintainer-supplied evidence to a queued candidate.
func (q *Queue) SetEvidence(key Key, evidence string, confidence catalog.Confidence) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	c, ok := q.candidates[key]
	if !ok {
		return fmt.Errorf("reviewqueue: unknown candidate %+v", key)
	}
	if evidence == "" {
		return fmt.Errorf("reviewqueue: evidence must not be empty")
	}
	c.Evidence = evidence
	c.Confidence = confidence
	if q.store != nil {
		return q.store.append(record{
			Kind:       kindEvidence,
			Timestamp:  time.Now(),
			Identity:   key.Identity,
			Host:       key.Host,
			Verdict:    key.Verdict,
			Evidence:   evidence,
			Confidence: confidence,
		})
	}
	return nil
}

// Approve is the only path that converts a candidate into a catalog.Entry.
func (q *Queue) Approve(cat *catalog.Catalog, key Key) (catalog.Entry, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	c, ok := q.candidates[key]
	if !ok {
		return catalog.Entry{}, fmt.Errorf("reviewqueue: unknown candidate %+v", key)
	}
	if c.Evidence == "" {
		return catalog.Entry{}, fmt.Errorf("reviewqueue: cannot approve %+v: no evidence on file", key)
	}
	if c.Confidence != catalog.ConfidenceHigh && c.Confidence != catalog.ConfidenceMedium {
		return catalog.Entry{}, fmt.Errorf("reviewqueue: cannot approve %+v: invalid confidence %q", key, c.Confidence)
	}
	entry := catalog.Entry{
		SchemaVersion: catalog.CurrentSchemaVersion,
		Identity:      key.Identity,
		Explanation:   fmt.Sprintf("promoted from review queue: %d reports", c.Count),
		Evidence:      c.Evidence,
		Confidence:    c.Confidence,
		Layer:         "baseline",
	}
	switch key.Verdict {
	case "allow":
		entry.ExpectedDestinations = []catalog.Destination{{Host: key.Host, Why: c.Evidence}}
	case "deny":
		entry.Never = []string{key.Host}
	default:
		return catalog.Entry{}, fmt.Errorf("reviewqueue: unknown verdict %q", key.Verdict)
	}
	if err := cat.Add(entry); err != nil {
		return catalog.Entry{}, fmt.Errorf("reviewqueue: catalog.Add: %w", err)
	}
	c.Status = StatusApproved
	if q.store != nil {
		if err := q.store.append(record{
			Kind:      kindApprove,
			Timestamp: time.Now(),
			Identity:  key.Identity,
			Host:      key.Host,
			Verdict:   key.Verdict,
		}); err != nil {
			return entry, err
		}
	}
	return entry, nil
}

// Reject marks a candidate rejected by explicit maintainer action.
func (q *Queue) Reject(key Key, reason string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	c, ok := q.candidates[key]
	if !ok {
		return fmt.Errorf("reviewqueue: unknown candidate %+v", key)
	}
	c.Status = StatusRejected
	if q.store != nil {
		return q.store.append(record{
			Kind:      kindReject,
			Timestamp: time.Now(),
			Identity:  key.Identity,
			Host:      key.Host,
			Verdict:   key.Verdict,
			Reason:    reason,
		})
	}
	return nil
}
