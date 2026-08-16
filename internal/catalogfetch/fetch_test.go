package catalogfetch

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/catalogsig"
)

const validBaselineTOML = `
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

func TestFetchVerified_RejectsBadSignature(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	mux := http.NewServeMux()
	mux.HandleFunc("/c", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(validBaselineTOML))
	})
	mux.HandleFunc("/c.sig", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not a real signature"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "catalog-baseline.toml")
	err := FetchVerified(context.Background(), srv.URL+"/c", srv.URL+"/c.sig", dest, HTTPFetcher{}, pub)
	if err == nil {
		t.Fatal("expected FetchVerified to reject an unsigned catalog")
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Error("no file must be written when signature verification fails")
	}
}

func TestFetchVerified_InstallsSignedCatalog(t *testing.T) {
	pub, priv, err := catalogsig.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	sig, err := catalogsig.Sign([]byte(validBaselineTOML), priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/c", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(validBaselineTOML))
	})
	mux.HandleFunc("/c.sig", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(sig)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "catalog-baseline.toml")
	if err := FetchVerified(context.Background(), srv.URL+"/c", srv.URL+"/c.sig", dest, HTTPFetcher{}, pub); err != nil {
		t.Fatalf("FetchVerified: %v", err)
	}
	if _, err := catalog.LoadFile(dest); err != nil {
		t.Fatalf("installed signed catalog is invalid: %v", err)
	}
}

func TestFetchVerified_RejectsEmptyCatalogAndPreservesExisting(t *testing.T) {
	pub, priv, err := catalogsig.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	empty := []byte("")
	sig, err := catalogsig.Sign(empty, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/c", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(empty)
	})
	mux.HandleFunc("/c.sig", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(sig)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "catalog-baseline.toml")
	if err := os.WriteFile(dest, []byte(validBaselineTOML), 0o644); err != nil {
		t.Fatalf("seed existing catalog: %v", err)
	}
	err = FetchVerified(context.Background(), srv.URL+"/c", srv.URL+"/c.sig", dest, HTTPFetcher{}, pub)
	if err == nil {
		t.Fatal("expected FetchVerified to reject a signed-but-empty catalog")
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read preserved catalog: %v", err)
	}
	if string(got) != validBaselineTOML {
		t.Fatalf("existing catalog was replaced by empty body:\n%s", got)
	}
}

func TestHTTPFetcher_RejectsPlainRemoteHTTP(t *testing.T) {
	_, err := (HTTPFetcher{}).Fetch(context.Background(), "http://example.com/catalog.toml")
	if err == nil {
		t.Fatal("expected plain remote HTTP to be rejected before download")
	}
}
