package reviewqueue

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/telemetry"
)

type recordKind string

const (
	kindReport   recordKind = "report"
	kindEvidence recordKind = "evidence"
	kindApprove  recordKind = "approve"
	kindReject   recordKind = "reject"
)

type record struct {
	Kind       recordKind         `json:"kind"`
	Timestamp  time.Time          `json:"ts"`
	Report     *telemetry.Report  `json:"report,omitempty"`
	Identity   catalog.Identity   `json:"identity,omitempty"`
	Host       string             `json:"host,omitempty"`
	Verdict    string             `json:"verdict,omitempty"`
	Evidence   string             `json:"evidence,omitempty"`
	Confidence catalog.Confidence `json:"confidence,omitempty"`
	Reason     string             `json:"reason,omitempty"`
}

type store struct {
	f *os.File
}

// Open loads path by replaying every JSONL record, then keeps it open for appends.
func Open(path string) (*Queue, error) {
	if path == "" {
		return nil, fmt.Errorf("reviewqueue: queue path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("reviewqueue: mkdir for %s: %w", path, err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, fmt.Errorf("reviewqueue: open %s: %w", path, err)
	}
	q := New()
	q.store = &store{f: f}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		var rec record
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			q.corruptRecords++
			continue
		}
		if err := q.replay(rec); err != nil {
			q.corruptRecords++
			continue
		}
	}
	if err := sc.Err(); err != nil {
		f.Close()
		return nil, fmt.Errorf("reviewqueue: scan %s: %w", path, err)
	}
	return q, nil
}

func (q *Queue) replay(rec record) error {
	switch rec.Kind {
	case kindReport:
		if rec.Report == nil {
			return fmt.Errorf("report record missing report")
		}
		return q.ingestLocked(*rec.Report, rec.Timestamp, false)
	case kindEvidence:
		if c := q.candidates[Key{Identity: rec.Identity, Host: rec.Host, Verdict: rec.Verdict}]; c != nil {
			c.Evidence = rec.Evidence
			c.Confidence = rec.Confidence
		}
	case kindApprove:
		if c := q.candidates[Key{Identity: rec.Identity, Host: rec.Host, Verdict: rec.Verdict}]; c != nil {
			c.Status = StatusApproved
		}
	case kindReject:
		if c := q.candidates[Key{Identity: rec.Identity, Host: rec.Host, Verdict: rec.Verdict}]; c != nil {
			c.Status = StatusRejected
		}
	default:
		return fmt.Errorf("unknown record kind %q", rec.Kind)
	}
	return nil
}

func (s *store) append(rec record) error {
	b, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("reviewqueue: marshal record: %w", err)
	}
	b = append(b, '\n')
	if _, err := s.f.Write(b); err != nil {
		return fmt.Errorf("reviewqueue: write record: %w", err)
	}
	return nil
}

// Close releases the backing file. It is safe on in-memory queues.
func (q *Queue) Close() error {
	if q.store == nil {
		return nil
	}
	return q.store.f.Close()
}
