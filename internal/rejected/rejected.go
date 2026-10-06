// Package rejected persists the baseline pairs a user has disowned.
package rejected

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type Key struct {
	ExeBasename string `json:"exe_basename"`
	ExeSHA256   string `json:"exe_sha256,omitempty"`
	TeamID      string `json:"team_id,omitempty"`
	Host        string `json:"host"`
}
type Record struct {
	Key Key       `json:"key"`
	Why string    `json:"why,omitempty"`
	At  time.Time `json:"at"`
}
type Store struct {
	mu          sync.Mutex
	path        string
	records     map[Key]Record
	quarantined bool
}

func Open(path string) (*Store, error) {
	s := &Store{path: path}
	if _, err := os.Stat(path + ".corrupt"); err == nil {
		s.quarantined = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := s.reload(); err != nil {
		if !errors.Is(err, errCorrupt) {
			return nil, err
		}
		if renameErr := os.Rename(path, path+".corrupt"); renameErr != nil {
			return nil, fmt.Errorf("rejected: quarantine corrupt store: %w", renameErr)
		}
		s.records = map[Key]Record{}
		s.quarantined = true
	}
	return s, nil
}

// OpenReadOnly never creates or quarantines a file. Calibration is observational.
func OpenReadOnly(path string) (*Store, error) {
	s := &Store{path: path}
	if _, err := os.Stat(path + ".corrupt"); err == nil {
		return nil, fmt.Errorf("rejected: quarantined rejection history at %s.corrupt", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := s.reload(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) Quarantined() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.quarantined }

var errCorrupt = errors.New("corrupt rejection store")

func (s *Store) reload() error {
	f, err := os.Open(s.path)
	if errors.Is(err, os.ErrNotExist) {
		s.records = map[Key]Record{}
		return nil
	}
	if err != nil {
		return fmt.Errorf("rejected: open: %w", err)
	}
	defer f.Close()
	records := map[Key]Record{}
	dec := json.NewDecoder(f)
	for {
		var rec Record
		err := dec.Decode(&rec)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("%w: %v", errCorrupt, err)
		}
		rec.Key = normalize(rec.Key)
		records[rec.Key] = rec
	}
	s.records = records
	return nil
}

func (s *Store) Reject(k Key, why string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.reload(); err != nil {
		return err
	}
	k = normalize(k)
	s.records[k] = Record{Key: k, Why: why, At: time.Now().UTC()}
	return s.flush()
}
func (s *Store) Restore(k Key) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.reload(); err != nil {
		return err
	}
	delete(s.records, normalize(k))
	return s.flush()
}
func (s *Store) Contains(k Key) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.records[normalize(k)]
	return ok
}
func (s *Store) List() []Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Record, 0, len(s.records))
	for _, rec := range s.records {
		out = append(out, rec)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].At.Equal(out[j].At) {
			return out[i].At.After(out[j].At)
		}
		return keyText(out[i].Key) < keyText(out[j].Key)
	})
	return out
}
func keyText(k Key) string {
	return k.ExeBasename + "\x00" + k.ExeSHA256 + "\x00" + k.TeamID + "\x00" + k.Host
}

func normalize(k Key) Key { k.Host = strings.ToLower(k.Host); return k }
func (s *Store) Digest() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	keys := make([]string, 0, len(s.records))
	for k := range s.records {
		keys = append(keys, keyText(k))
	}
	sort.Strings(keys)
	h := sha256.New()
	for _, k := range keys {
		_, _ = h.Write([]byte(k))
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}
func (s *Store) Refresh() error { s.mu.Lock(); defer s.mu.Unlock(); return s.reload() }

func (s *Store) flush() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(s.path), ".rejected-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	enc := json.NewEncoder(f)
	for _, rec := range s.listUnlocked() {
		if err := enc.Encode(rec); err != nil {
			f.Close()
			return err
		}
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
func (s *Store) listUnlocked() []Record {
	out := make([]Record, 0, len(s.records))
	for _, rec := range s.records {
		out = append(out, rec)
	}
	sort.Slice(out, func(i, j int) bool { return keyText(out[i].Key) < keyText(out[j].Key) })
	return out
}
