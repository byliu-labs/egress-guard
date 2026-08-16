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

const cliValidIssuedBaselineTOML = "issued_at = \"2026-08-16T00:00:00Z\"\n" + cliValidBaselineTOML

func TestCatalog_FetchWithPubkeyVerifiesSignature(t *testing.T) {
	pub, priv, err := catalogsig.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	sig, err := catalogsig.Sign([]byte(cliValidIssuedBaselineTOML), priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/catalog.toml", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(cliValidIssuedBaselineTOML))
	})
	mux.HandleFunc("/catalog.toml.sig", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(sig)
	})
	srv := httptest.NewTLSServer(mux)
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

func TestCatalog_FetchSystemInstallsDaemonBaseline(t *testing.T) {
	pub, priv, err := catalogsig.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	sig, err := catalogsig.Sign([]byte(cliValidIssuedBaselineTOML), priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/catalog.toml", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(cliValidIssuedBaselineTOML))
	})
	mux.HandleFunc("/catalog.toml.sig", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(sig)
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	catalogFetcher = catalogfetch.HTTPFetcher{Client: srv.Client()}
	t.Cleanup(func() { catalogFetcher = catalogfetch.HTTPFetcher{} })

	userCfg := t.TempDir()
	systemDest := filepath.Join(t.TempDir(), "var-db-egress-guard", ".config", "egress-guard", "catalog-baseline.toml")
	t.Setenv("XDG_CONFIG_HOME", userCfg)
	pubPath := filepath.Join(t.TempDir(), "catalog.pub")
	if err := os.WriteFile(pubPath, pub, 0o644); err != nil {
		t.Fatalf("write pubkey: %v", err)
	}
	stubEuid(t, 0)
	prevSystemPath := catalogSystemBaselinePath
	catalogSystemBaselinePath = func() (string, error) { return systemDest, nil }
	t.Cleanup(func() { catalogSystemBaselinePath = prevSystemPath })

	if err := Catalog([]string{"fetch", "--system", "--url", srv.URL + "/catalog.toml", "--pubkey", pubPath}); err != nil {
		t.Fatalf("Catalog signed system fetch: %v", err)
	}
	if _, err := catalog.LoadFile(systemDest); err != nil {
		t.Fatalf("expected installed system catalog at %s: %v", systemDest, err)
	}
	userDest := filepath.Join(userCfg, "egress-guard", "catalog-baseline.toml")
	if _, err := os.Stat(userDest); !os.IsNotExist(err) {
		t.Fatalf("--system must not install user catalog %s", userDest)
	}
}

func TestCatalog_FetchSystemRequiresRootBeforeDownload(t *testing.T) {
	requests := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		_, _ = w.Write([]byte(cliValidIssuedBaselineTOML))
	}))
	defer srv.Close()
	catalogFetcher = catalogfetch.HTTPFetcher{Client: srv.Client()}
	t.Cleanup(func() { catalogFetcher = catalogfetch.HTTPFetcher{} })

	stubEuid(t, 501)
	if err := Catalog([]string{"fetch", "--system", "--url", srv.URL + "/catalog.toml"}); err == nil {
		t.Fatal("expected --system fetch as non-root to fail")
	} else if !strings.Contains(err.Error(), "requires root") {
		t.Fatalf("error %q does not tell the user root is required", err)
	}
	if requests != 0 {
		t.Fatalf("--system non-root made %d network requests before failing", requests)
	}
}

func TestCatalog_DefaultFetchRequiresSignedCatalog(t *testing.T) {
	signatureRequests := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".sig") {
			signatureRequests++
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte("issued_at = \"2026-08-17T00:00:00Z\"\n" + cliValidBaselineTOML))
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
