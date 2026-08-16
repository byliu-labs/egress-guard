package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/catalogsig"
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

func TestRun_KeygenAndSignProduceVerifiableArtifact(t *testing.T) {
	dir := t.TempDir()
	pubPath := filepath.Join(dir, "catalog.pub")
	privPath := filepath.Join(dir, "catalog.priv")
	if err := run([]string{"keygen", "--pub-out", pubPath, "--priv-out", privPath}); err != nil {
		t.Fatalf("run keygen: %v", err)
	}
	info, err := os.Stat(privPath)
	if err != nil {
		t.Fatalf("stat private key: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("private key permissions = %o, want 600", info.Mode().Perm())
	}

	catalogPath := filepath.Join(dir, "catalog-baseline.toml")
	if err := run([]string{"build", "--baseline", "../../catalog/baseline", "--out", catalogPath}); err != nil {
		t.Fatalf("run build: %v", err)
	}
	sigPath := filepath.Join(dir, "catalog-baseline.toml.sig")
	if err := run([]string{"sign", "--catalog", catalogPath, "--private-key", privPath, "--sig-out", sigPath}); err != nil {
		t.Fatalf("run sign: %v", err)
	}

	data, err := os.ReadFile(catalogPath)
	if err != nil {
		t.Fatalf("read catalog: %v", err)
	}
	sig, err := os.ReadFile(sigPath)
	if err != nil {
		t.Fatalf("read signature: %v", err)
	}
	pub, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatalf("read public key: %v", err)
	}
	if err := catalogsig.Verify(data, sig, pub); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}
}

func TestRun_UnknownSubcommand(t *testing.T) {
	if err := run([]string{"frobnicate"}); err == nil {
		t.Error("expected error for unknown subcommand")
	}
}
