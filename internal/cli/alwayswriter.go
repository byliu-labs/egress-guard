package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/BurntSushi/toml"
	"github.com/byliu-labs/egress-guard/internal/allowlist"
	"github.com/byliu-labs/egress-guard/internal/config"
)

// alwaysWriter implements prompt.AlwaysWriter. It persists the user's
// "Allow always"/"Deny always" choice two ways simultaneously:
//
//   1. To the user allowlist file (~/.config/egress-guard/allowlist.toml)
//      — survives daemon restarts.
//   2. Into the live *allowlist.Allowlist — so the next connection from
//      any process to the same registered domain is auto-decided without
//      re-prompting, no daemon reload required.
//
// The pattern written is `**.{regdom}` which matches the registered domain
// itself plus every subdomain (see allowlist/matcher.go). That mirrors what
// the prompt body says ("Allow this destination?") and what the burst
// coalescer groups by.
type alwaysWriter struct {
	path string
	al   *allowlist.Allowlist
	mu   sync.Mutex // serializes file read-modify-write
}

func newAlwaysWriter(path string, al *allowlist.Allowlist) *alwaysWriter {
	return &alwaysWriter{path: path, al: al}
}

func (w *alwaysWriter) AddAllow(regdom string) error { return w.add(regdom, true) }
func (w *alwaysWriter) AddDeny(regdom string) error  { return w.add(regdom, false) }

func (w *alwaysWriter) add(regdom string, allow bool) error {
	if regdom == "" {
		return errors.New("alwayswriter: empty regdom")
	}
	pattern := "**." + regdom

	w.mu.Lock()
	defer w.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(w.path), 0o755); err != nil {
		return fmt.Errorf("alwayswriter: mkdir: %w", err)
	}
	cur, err := config.LoadFromFile(w.path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("alwayswriter: read %s: %w", w.path, err)
	}

	if allow {
		if !contains(cur.Allow, pattern) {
			cur.Allow = append(cur.Allow, pattern)
		}
	} else {
		if !contains(cur.Deny, pattern) {
			cur.Deny = append(cur.Deny, pattern)
		}
	}

	if err := writeTomlAtomic(w.path, cur); err != nil {
		return err
	}

	if allow {
		w.al.AddUserAllow(pattern)
	} else {
		w.al.AddUserDeny(pattern)
	}
	return nil
}

func writeTomlAtomic(path string, r config.Resolved) error {
	out := config.File{
		Allow: config.Section{Hosts: r.Allow},
		Deny:  config.Section{Hosts: r.Deny},
	}
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return fmt.Errorf("alwayswriter: create %s: %w", tmp, err)
	}
	if err := toml.NewEncoder(f).Encode(out); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("alwayswriter: encode: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("alwayswriter: close: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("alwayswriter: rename: %w", err)
	}
	return nil
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
