package config

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

// File is the on-disk TOML schema. We keep it simple: two lists.
type File struct {
	Allow Section `toml:"allow"`
	Deny  Section `toml:"deny"`
}

type Section struct {
	Hosts []string `toml:"hosts"`
}

// Resolved is what the daemon consumes: flat allow/deny slices.
type Resolved struct {
	Allow []string
	Deny  []string
}

// LoadFromString parses TOML from a string. Used by tests and by the embedded
// defaults loader.
func LoadFromString(s string) (Resolved, error) {
	var f File
	if _, err := toml.Decode(s, &f); err != nil {
		return Resolved{}, fmt.Errorf("config: parse: %w", err)
	}
	return Resolved{Allow: f.Allow.Hosts, Deny: f.Deny.Hosts}, nil
}

// LoadFromFile parses TOML from disk. Returns os.ErrNotExist if the file does
// not exist (callers may treat this as "use defaults").
func LoadFromFile(path string) (Resolved, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return Resolved{}, os.ErrNotExist
	}
	if err != nil {
		return Resolved{}, fmt.Errorf("config: read %s: %w", path, err)
	}
	return LoadFromString(string(b))
}
