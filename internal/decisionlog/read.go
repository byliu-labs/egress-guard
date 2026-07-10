package decisionlog

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// Filter narrows Read's output. Zero values mean no filter on that dimension.
type Filter struct {
	Since time.Time
	Until time.Time
	Host  string
	PID   int
}

// Read parses every entry in the decision log at path, in file order.
func Read(path string) ([]Entry, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("decisionlog: read %s: %w", path, err)
	}
	trimmed := strings.TrimRight(string(b), "\n")
	if trimmed == "" {
		return nil, nil
	}
	lines := strings.Split(trimmed, "\n")
	entries := make([]Entry, 0, len(lines))
	for i, line := range lines {
		var e Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			if i == len(lines)-1 {
				break
			}
			return nil, fmt.Errorf("decisionlog: corrupt entry at line %d of %s: %w", i+1, path, err)
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// ReadFilter is Read narrowed by f.
func ReadFilter(path string, f Filter) ([]Entry, error) {
	all, err := Read(path)
	if err != nil {
		return nil, err
	}
	out := make([]Entry, 0, len(all))
	for _, e := range all {
		if f.Host != "" && e.Host != f.Host {
			continue
		}
		if f.PID != 0 && e.PID != f.PID {
			continue
		}
		if !f.Since.IsZero() || !f.Until.IsZero() {
			ts, err := time.Parse(time.RFC3339, e.Timestamp)
			if err != nil {
				continue
			}
			if !f.Since.IsZero() && ts.Before(f.Since) {
				continue
			}
			if !f.Until.IsZero() && ts.After(f.Until) {
				continue
			}
		}
		out = append(out, e)
	}
	return out, nil
}
