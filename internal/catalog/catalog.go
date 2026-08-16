// Package catalog defines the known-good identity catalog format: a versioned
// record of process identity and expected destination facts.
package catalog

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/BurntSushi/toml"
)

// CurrentSchemaVersion is the only schema_version this build accepts.
const CurrentSchemaVersion = 1

// Confidence is how strongly the catalog vouches for an entry.
type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
)

var validLayers = map[string]bool{"baseline": true, "pro": true, "user": true}

// Identity is the trust anchor for a catalog entry.
type Identity struct {
	ExeBasename    string `toml:"exe_basename,omitempty"`
	ExeSHA256      string `toml:"exe_sha256,omitempty" json:"-"`
	TeamID         string `toml:"team_id,omitempty"`
	BundleID       string `toml:"bundle_id,omitempty"`
	SignedRequired bool   `toml:"signed_required,omitempty"`
}

// Destination is one hostname an identity is expected to contact.
type Destination struct {
	Host string `toml:"host"`
	Why  string `toml:"why,omitempty"`
}

// Entry is one known-good identity and destination fact.
type Entry struct {
	SchemaVersion        int           `toml:"schema_version"`
	Identity             Identity      `toml:"identity"`
	ExpectedDestinations []Destination `toml:"expected_destinations,omitempty"`
	Never                []string      `toml:"never,omitempty"`
	Explanation          string        `toml:"explanation"`
	Evidence             string        `toml:"evidence"`
	Confidence           Confidence    `toml:"confidence"`
	Layer                string        `toml:"layer"`
}

type fileSchema struct {
	Entry []Entry `toml:"entry"`
}

// Catalog is a loaded, validated set of entries.
type Catalog struct {
	mu      sync.RWMutex
	entries []Entry
}

// LayerFile identifies one named catalog layer to load at startup.
type LayerFile struct {
	Name string
	Path string
}

// MatchResult is the answer to whether the catalog has a fact about an
// identity and host pairing. Found means the catalog can explain the prompt;
// Authoritative means it can decide without asking.
type MatchResult struct {
	Found         bool
	Entry         Entry
	NeverHit      bool
	Authoritative bool
}

// Load parses TOML bytes into a Catalog, rejecting invalid entries.
func Load(b []byte) (*Catalog, error) {
	var f fileSchema
	if _, err := toml.Decode(string(b), &f); err != nil {
		return nil, fmt.Errorf("catalog: parse: %w", err)
	}
	entries := make([]Entry, 0, len(f.Entry))
	for i, e := range f.Entry {
		if err := validateEntry(e); err != nil {
			return nil, fmt.Errorf("catalog: entry %d: %w", i, err)
		}
		entries = append(entries, e)
	}
	return &Catalog{entries: entries}, nil
}

// LoadFile parses a catalog TOML file from disk. Missing files pass through as
// os.ErrNotExist so callers can treat an absent user catalog as empty.
func LoadFile(path string) (*Catalog, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, os.ErrNotExist
	}
	if err != nil {
		return nil, fmt.Errorf("catalog: read %s: %w", path, err)
	}
	return Load(b)
}

// LoadLayers merges the supplied catalog layers in order. Missing files are
// empty layers; malformed or unreadable files prevent startup.
func LoadLayers(layers ...LayerFile) (*Catalog, error) {
	live := &Catalog{}
	for _, layer := range layers {
		loaded, err := LoadFile(layer.Path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("load %s catalog %s: %w", layer.Name, layer.Path, err)
		}
		live.Merge(loaded)
	}
	return live, nil
}

// Merge appends other's entries. Call only during startup, before concurrent
// lookups can observe mutation.
func (c *Catalog) Merge(other *Catalog) {
	if other == nil {
		return
	}
	other.mu.RLock()
	entries := append([]Entry(nil), other.entries...)
	other.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = append(c.entries, entries...)
}

// Lookup matches id and host against catalog facts. Name-only baseline/pro
// entries can explain a prompt, but only user-ratified entries or pinned
// entries can decide without asking.
func (c *Catalog) Lookup(id Identity, host string) MatchResult {
	nh := normalizeHost(host)
	var expected MatchResult
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, e := range c.entries {
		if !identityDescribes(e.Identity, id) {
			continue
		}
		authoritative := entryCanDecide(e)
		for _, never := range e.Never {
			if normalizeHost(never) == nh {
				return MatchResult{Found: true, Entry: e, NeverHit: true, Authoritative: authoritative}
			}
		}
		for _, d := range e.ExpectedDestinations {
			if normalizeHost(d.Host) == nh {
				if !expected.Found || (!expected.Authoritative && authoritative) {
					expected = MatchResult{Found: true, Entry: e, Authoritative: authoritative}
				}
			}
		}
	}
	return expected
}

// HasHost reports whether host appears anywhere in the catalog as an expected
// destination or an explicit never destination.
func (c *Catalog) HasHost(host string) bool {
	nh := normalizeHost(host)
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, e := range c.entries {
		for _, never := range e.Never {
			if normalizeHost(never) == nh {
				return true
			}
		}
		for _, d := range e.ExpectedDestinations {
			if normalizeHost(d.Host) == nh {
				return true
			}
		}
	}
	return false
}

// EntryCount returns the number of validated entries in the catalog.
func (c *Catalog) EntryCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// Add validates e and appends it to the catalog.
func (c *Catalog) Add(e Entry) error {
	if err := validateEntry(e); err != nil {
		return fmt.Errorf("catalog: add: %w", err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = append(c.entries, e)
	return nil
}

// Marshal serializes the catalog to TOML, round-trippable through Load.
func (c *Catalog) Marshal() ([]byte, error) {
	c.mu.RLock()
	entries := append([]Entry(nil), c.entries...)
	c.mu.RUnlock()

	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(fileSchema{Entry: entries}); err != nil {
		return nil, fmt.Errorf("catalog: marshal: %w", err)
	}
	return buf.Bytes(), nil
}

func identityDescribes(entryID, queryID Identity) bool {
	if entryID.ExeSHA256 == "" && entryID.BundleID == "" && entryID.TeamID == "" && entryID.ExeBasename == "" {
		return false
	}
	if entryID.ExeSHA256 != "" && !strings.EqualFold(entryID.ExeSHA256, queryID.ExeSHA256) {
		return false
	}
	if entryID.BundleID != "" && entryID.BundleID != queryID.BundleID {
		return false
	}
	if entryID.TeamID != "" && entryID.TeamID != queryID.TeamID {
		return false
	}
	if entryID.ExeBasename != "" && entryID.ExeBasename != queryID.ExeBasename {
		return false
	}
	return true
}

func entryCanDecide(e Entry) bool {
	return e.Layer == "user" || hasDecisionPin(e.Identity)
}

func hasDecisionPin(id Identity) bool {
	return id.ExeSHA256 != "" || id.TeamID != "" || id.BundleID != ""
}

func normalizeHost(h string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
}

func validateEntry(e Entry) error {
	if e.Identity.ExeSHA256 == "" && e.Identity.BundleID == "" && e.Identity.TeamID == "" && e.Identity.ExeBasename == "" {
		return fmt.Errorf("empty identity: at least one identity field required")
	}
	if e.Evidence == "" {
		return fmt.Errorf("missing evidence: a catalog fact requires evidence")
	}
	if e.Explanation == "" {
		return fmt.Errorf("missing explanation: drift-prompt text is required")
	}
	switch e.Confidence {
	case ConfidenceHigh, ConfidenceMedium:
	default:
		return fmt.Errorf("invalid confidence %q: must be %q or %q", e.Confidence, ConfidenceHigh, ConfidenceMedium)
	}
	if e.Confidence == ConfidenceHigh && e.Identity.TeamID == "" && e.Identity.BundleID == "" {
		return fmt.Errorf("confidence %q requires a signature anchor", ConfidenceHigh)
	}
	if !validLayers[e.Layer] {
		return fmt.Errorf("invalid layer %q: must be baseline, pro, or user", e.Layer)
	}
	if e.SchemaVersion != CurrentSchemaVersion {
		return fmt.Errorf("unsupported schema_version %d: this build supports %d", e.SchemaVersion, CurrentSchemaVersion)
	}
	return nil
}
