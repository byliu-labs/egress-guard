package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/exempt"
)

func TestRun_BuildOfflineRoundTrips(t *testing.T) {
	out := filepath.Join(t.TempDir(), "catalog-baseline.toml")
	if err := run([]string{"build", "--baseline", "../../catalog/baseline", "--out", out}); err != nil {
		t.Fatalf("run build: %v", err)
	}
	c, err := catalog.LoadFile(out)
	if err != nil {
		t.Fatalf("compiled output does not load: %v", err)
	}
	if !c.HasHost("registry.npmjs.org") {
		t.Error("compiled catalog missing registry.npmjs.org")
	}
}

func TestRun_RefreshUsesKnownGoodFragments(t *testing.T) {
	out := filepath.Join(t.TempDir(), "catalog-baseline.toml")
	if err := run([]string{"refresh", "--baseline", "../../catalog/baseline", "--out", out}); err != nil {
		t.Fatalf("run refresh: %v", err)
	}
	c, err := catalog.LoadFile(out)
	if err != nil {
		t.Fatalf("refreshed output does not load: %v", err)
	}
	if !c.HasHost("pypi.org") {
		t.Error("refreshed catalog missing pypi.org")
	}
}

func TestRun_EmbedExemptWritesFile(t *testing.T) {
	out := filepath.Join(t.TempDir(), "defaults_embedded.toml")
	if err := run([]string{"embed-exempt", "--exempt", "../../catalog/exempt", "--out", out}); err != nil {
		t.Fatalf("run embed-exempt: %v", err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read embedded exempt output: %v", err)
	}
	if len(b) == 0 {
		t.Fatal("embed-exempt produced an empty file")
	}
	if _, err := exempt.LoadFromString(string(b)); err != nil {
		t.Fatalf("embedded exempt output does not parse: %v", err)
	}
}

func TestRun_UnknownSubcommand(t *testing.T) {
	if err := run([]string{"frobnicate"}); err == nil {
		t.Error("expected error for unknown subcommand")
	}
}
