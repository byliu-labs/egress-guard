package cli

import (
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/byliu-labs/egress-guard/internal/catalog"
)

const cliValidBaselineTOML = `
[[entry]]
schema_version = 1
layer = "baseline"
confidence = "medium"
evidence = "test fixture"
explanation = "test entry"

[entry.identity]
exe_basename = "pip"

[[entry.expected_destinations]]
host = "pypi.org"
`

func TestCatalog_FetchInstallsAtBaselinePath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(cliValidBaselineTOML))
	}))
	defer srv.Close()

	cfg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", cfg)

	if err := Catalog([]string{"fetch", "--url", srv.URL}); err != nil {
		t.Fatalf("Catalog fetch: %v", err)
	}
	want := filepath.Join(cfg, "egress-guard", "catalog-baseline.toml")
	if _, err := catalog.LoadFile(want); err != nil {
		t.Fatalf("expected an installed catalog at %s: %v", want, err)
	}
}

func TestCatalog_FetchWithPubkeyVerifiesSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	sig := ed25519.Sign(priv, []byte(cliValidBaselineTOML))
	mux := http.NewServeMux()
	mux.HandleFunc("/catalog.toml", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(cliValidBaselineTOML))
	})
	mux.HandleFunc("/catalog.toml.sig", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(sig)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", cfg)
	pubPath := filepath.Join(t.TempDir(), "catalog.pub")
	if err := os.WriteFile(pubPath, pub, 0o644); err != nil {
		t.Fatalf("write pubkey: %v", err)
	}

	if err := Catalog([]string{"fetch", "--url", srv.URL + "/catalog.toml", "--pubkey", pubPath}); err != nil {
		t.Fatalf("Catalog signed fetch: %v", err)
	}
	want := filepath.Join(cfg, "egress-guard", "catalog-baseline.toml")
	if _, err := catalog.LoadFile(want); err != nil {
		t.Fatalf("expected an installed signed catalog at %s: %v", want, err)
	}
}

func TestCatalog_UnknownSubcommand(t *testing.T) {
	if err := Catalog([]string{"wat"}); err == nil {
		t.Error("expected error for unknown catalog subcommand")
	}
}
