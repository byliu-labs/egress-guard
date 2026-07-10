package cli

import (
	"path/filepath"
	"testing"

	"github.com/byliu-labs/egress-guard/internal/allowlist"
	"github.com/byliu-labs/egress-guard/internal/config"
)

func TestAlwaysWriter_AddAllow_WritesFileAndUpdatesLive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allowlist.toml")
	al := allowlist.New(allowlist.Config{})
	w := newAlwaysWriter(path, al)

	if err := w.AddAllow("github.com"); err != nil {
		t.Fatalf("AddAllow: %v", err)
	}

	// File contains the wildcard pattern.
	got, err := config.LoadFromFile(path)
	if err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}
	if len(got.Allow) != 1 || got.Allow[0] != "**.github.com" {
		t.Errorf("file Allow = %v, want [**.github.com]", got.Allow)
	}

	// Live allowlist now permits the registered domain and any subdomain.
	if d := al.Decide("github.com"); d != allowlist.Allow {
		t.Errorf("Decide(github.com) = %v, want Allow (live mutation should match)", d)
	}
	if d := al.Decide("api.github.com"); d != allowlist.Allow {
		t.Errorf("Decide(api.github.com) = %v, want Allow (subdomain match)", d)
	}
	if d := al.Decide("notgithub.com"); d != allowlist.Unknown {
		t.Errorf("Decide(notgithub.com) = %v, want Unknown (no match)", d)
	}
}

func TestAlwaysWriter_AddDeny_WritesFileAndUpdatesLive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allowlist.toml")
	al := allowlist.New(allowlist.Config{})
	w := newAlwaysWriter(path, al)

	if err := w.AddDeny("evil.com"); err != nil {
		t.Fatalf("AddDeny: %v", err)
	}

	got, _ := config.LoadFromFile(path)
	if len(got.Deny) != 1 || got.Deny[0] != "**.evil.com" {
		t.Errorf("file Deny = %v, want [**.evil.com]", got.Deny)
	}
	if d := al.Decide("api.evil.com"); d != allowlist.Deny {
		t.Errorf("Decide(api.evil.com) = %v, want Deny", d)
	}
}

func TestAlwaysWriter_Idempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allowlist.toml")
	al := allowlist.New(allowlist.Config{})
	w := newAlwaysWriter(path, al)

	for range 3 {
		if err := w.AddAllow("github.com"); err != nil {
			t.Fatalf("AddAllow: %v", err)
		}
	}

	got, _ := config.LoadFromFile(path)
	if len(got.Allow) != 1 {
		t.Errorf("file Allow length = %d, want 1 (idempotent), got %v", len(got.Allow), got.Allow)
	}
}

func TestAlwaysWriter_PreservesExistingEntries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allowlist.toml")
	al := allowlist.New(allowlist.Config{})

	// Pre-seed with an entry the user added via the CLI.
	if err := writeTomlAtomic(path, config.Resolved{
		Allow: []string{"existing.example"},
		Deny:  []string{"banned.example"},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	w := newAlwaysWriter(path, al)
	if err := w.AddAllow("github.com"); err != nil {
		t.Fatalf("AddAllow: %v", err)
	}

	got, _ := config.LoadFromFile(path)
	if len(got.Allow) != 2 || got.Allow[0] != "existing.example" || got.Allow[1] != "**.github.com" {
		t.Errorf("file Allow = %v, want [existing.example **.github.com]", got.Allow)
	}
	if len(got.Deny) != 1 || got.Deny[0] != "banned.example" {
		t.Errorf("file Deny = %v, want [banned.example] (preserved)", got.Deny)
	}
}

func TestAlwaysWriter_RejectsEmptyRegdom(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allowlist.toml")
	w := newAlwaysWriter(path, allowlist.New(allowlist.Config{}))

	if err := w.AddAllow(""); err == nil {
		t.Error("AddAllow(\"\") = nil, want error")
	}
	if err := w.AddDeny(""); err == nil {
		t.Error("AddDeny(\"\") = nil, want error")
	}
}
