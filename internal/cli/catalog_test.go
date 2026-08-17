package cli

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/catalogfetch"
	"github.com/byliu-labs/egress-guard/internal/catalogsig"
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

func TestCatalog_FetchWithPubkeyVerifiesSignature(t *testing.T) {
	pub, priv, err := catalogsig.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	sig, err := catalogsig.Sign([]byte(cliValidBaselineTOML), priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/catalog.toml", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(cliValidBaselineTOML))
	})
	mux.HandleFunc("/catalog.toml.sig", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(sig)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	catalogFetcher = catalogfetch.HTTPFetcher{Client: srv.Client()}
	t.Cleanup(func() { catalogFetcher = catalogfetch.HTTPFetcher{} })

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

func TestCatalog_DefaultFetchRequiresSignedCatalog(t *testing.T) {
	signatureRequests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".sig") {
			signatureRequests++
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(cliValidBaselineTOML))
	}))
	defer srv.Close()
	catalogFetcher = catalogfetch.HTTPFetcher{Client: srv.Client()}
	t.Cleanup(func() { catalogFetcher = catalogfetch.HTTPFetcher{} })

	cfg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", cfg)

	if err := Catalog([]string{"fetch", "--url", srv.URL + "/catalog.toml"}); err == nil {
		t.Fatal("expected unsigned catalog fetch to be refused")
	} else if !strings.Contains(err.Error(), ".sig") {
		t.Fatalf("error %q does not name the missing signature", err)
	}
	if signatureRequests != 1 {
		t.Fatalf("default fetch made %d signature requests, want 1", signatureRequests)
	}
	want := filepath.Join(cfg, "egress-guard", "catalog-baseline.toml")
	if _, err := os.Stat(want); !os.IsNotExist(err) {
		t.Fatalf("unsigned fetch must not install %s", want)
	}
}

func TestCatalog_UnknownSubcommand(t *testing.T) {
	if err := Catalog([]string{"wat"}); err == nil {
		t.Error("expected error for unknown catalog subcommand")
	}
}
