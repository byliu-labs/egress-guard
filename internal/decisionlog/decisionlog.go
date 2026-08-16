// Package decisionlog records every egress decision the daemon adjudicates
// — allow, deny, or observe — as one JSON object per line.
package decisionlog

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/byliu-labs/egress-guard/internal/persist"
)

// Decision is the daemon's verdict on a connection.
type Decision string

const (
	DecisionAllow   Decision = "allow"
	DecisionDeny    Decision = "deny"
	DecisionObserve Decision = "observe"
)

// TrustTier records how a Decision was reached.
type TrustTier string

const (
	TierCatalogFact  TrustTier = "catalog_fact"
	TierPrompt       TrustTier = "prompt"
	TierDefault      TrustTier = "default"
	TierModelOpinion TrustTier = "model_opinion"
)

// Entry is one decision record. Old blocklog fields keep their JSON tags for
// compatibility with existing blocked.log consumers.
type Entry struct {
	Timestamp string    `json:"ts"`
	Decision  Decision  `json:"decision"`
	Action    string    `json:"action"`
	Reason    string    `json:"reason,omitempty"`
	TrustTier TrustTier `json:"trust_tier,omitempty"`
	PID       int       `json:"pid,omitempty"`
	PPID      int       `json:"ppid,omitempty"`
	Exe       string    `json:"exe,omitempty"`
	Comm      string    `json:"comm,omitempty"`
	Argv      []string  `json:"argv,omitempty"`
	Cwd       string    `json:"cwd,omitempty"`
	PName     string    `json:"pname,omitempty"`
	Host      string    `json:"host,omitempty"`
	DestIP    string    `json:"dest_ip,omitempty"`
	DestPort  int       `json:"dest_port,omitempty"`
	TeamID    string    `json:"team_id,omitempty"`
	SigValid  bool      `json:"sig_valid,omitempty"`
	// Persistence is best-effort enrichment from the daemon write path.
	// nil means attribution was not attempted or failed, not "no persistence".
	Persistence *persist.Source `json:"persistence,omitempty"`
}

// Writer wraps the underlying file with a mutex for goroutine-safe appends.
type Writer struct {
	mu   sync.Mutex
	f    *os.File
	path string
	size int64
	opts Options
	wg   sync.WaitGroup
}

// Open opens, creating if needed, the append-only log file at path.
func Open(path string) (*Writer, error) {
	return OpenWithOptions(path, Options{})
}

func openWriter(path string) (*Writer, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("decisionlog: mkdir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("decisionlog: open: %w", err)
	}
	return &Writer{f: f, path: path}, nil
}

// Write appends one entry as one mutex-guarded write.
func (w *Writer) Write(e Entry) error {
	if e.Timestamp == "" {
		e.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	b, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("decisionlog: marshal: %w", err)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return fmt.Errorf("decisionlog: write after close")
	}
	b = append(b, '\n')
	if w.opts.MaxBytes > 0 && w.size > 0 && w.size+int64(len(b)) > w.opts.MaxBytes {
		if err := w.rotateLocked(); err != nil {
			return err
		}
	}
	n, err := w.f.Write(b)
	w.size += int64(n)
	if err != nil {
		return fmt.Errorf("decisionlog: write: %w", err)
	}
	return nil
}

// Close closes the underlying file.
func (w *Writer) Close() error {
	w.mu.Lock()
	if w.f == nil {
		w.mu.Unlock()
		return nil
	}
	err := w.f.Close()
	w.f = nil
	w.mu.Unlock()
	w.wg.Wait()
	return err
}
