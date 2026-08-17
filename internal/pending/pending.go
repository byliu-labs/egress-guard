// Package pending holds local binary upgrades waiting for user review.
package pending

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Item is one changed binary awaiting review.
type Item struct {
	ExePath   string    `json:"exe_path"`
	Basename  string    `json:"basename"`
	OldSHA256 string    `json:"old_sha256"`
	NewSHA256 string    `json:"new_sha256"`
	Hosts     []string  `json:"hosts"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Count     int       `json:"count"`
}

type key struct {
	path string
	sum  string
}

// Store is a small persistent set, safe for concurrent daemon observations.
type Store struct {
	mu    sync.Mutex
	path  string
	items map[key]Item
	now   func() time.Time
}

// Open loads the pending queue. A missing file is an empty queue.
func Open(path string) (*Store, error) {
	s := &Store{path: path, items: make(map[key]Item), now: time.Now}
	if err := s.reloadLocked(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) reloadLocked() error {
	f, err := os.Open(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			s.items = make(map[key]Item)
			return nil
		}
		return fmt.Errorf("pending: open %s: %w", s.path, err)
	}
	defer f.Close()

	items := make(map[key]Item)
	dec := json.NewDecoder(f)
	for {
		var it Item
		if err := dec.Decode(&it); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return fmt.Errorf("pending: decode %s: %w", s.path, err)
		}
		items[key{path: it.ExePath, sum: it.NewSHA256}] = it
	}
	s.items = items
	return nil
}

// Record adds or merges a changed-binary observation.
func (s *Store) Record(it Item) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.reloadLocked(); err != nil {
		return err
	}

	now := s.now()
	k := key{path: it.ExePath, sum: it.NewSHA256}
	if prev, ok := s.items[k]; ok {
		prev.Count++
		prev.LastSeen = now
		prev.Hosts = mergeHosts(prev.Hosts, it.Hosts)
		s.items[k] = prev
	} else {
		it.Count = 1
		it.FirstSeen = now
		it.LastSeen = now
		it.Hosts = mergeHosts(nil, it.Hosts)
		s.items[k] = it
	}
	return s.flushLocked()
}

// Resolve removes an item after review.
func (s *Store) Resolve(exePath, newSHA string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.reloadLocked(); err != nil {
		return err
	}
	delete(s.items, key{path: exePath, sum: newSHA})
	return s.flushLocked()
}

// List returns items sorted newest observation first.
func (s *Store) List() ([]Item, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.reloadLocked(); err != nil {
		return nil, err
	}
	out := make([]Item, 0, len(s.items))
	for _, it := range s.items {
		out = append(out, it)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	return out, nil
}

// DistinctNewHashes reports how many replacement hashes are queued for exePath.
func (s *Store) DistinctNewHashes(exePath string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.reloadLocked(); err != nil {
		return 0, err
	}
	seen := map[string]bool{}
	for k := range s.items {
		if k.path == exePath {
			seen[k.sum] = true
		}
	}
	return len(seen), nil
}

func (s *Store) flushLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return fmt.Errorf("pending: mkdir: %w", err)
	}
	tmp := s.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("pending: write temp: %w", err)
	}
	enc := json.NewEncoder(f)
	for _, it := range s.items {
		if err := enc.Encode(it); err != nil {
			_ = f.Close()
			return fmt.Errorf("pending: encode: %w", err)
		}
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("pending: close temp: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("pending: install: %w", err)
	}
	return nil
}

func mergeHosts(a, b []string) []string {
	seen := make(map[string]bool, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, h := range append(append([]string{}, a...), b...) {
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// Count reports how many binaries await review.
func Count(path string) (int, error) {
	s, err := Open(path)
	if err != nil {
		return 0, err
	}
	return len(s.items), nil
}
