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

func TestFetch_InstallsValidCatalog(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(validBaselineTOML))
	}))
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "catalog-baseline.toml")
	if err := Fetch(context.Background(), srv.URL, dest, HTTPFetcher{}); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if _, err := catalog.LoadFile(dest); err != nil {
		t.Fatalf("installed catalog is invalid: %v", err)
	}
}

func TestFetch_RejectsInvalidCatalog_NoFileWritten(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("this is not valid catalog toml {{{"))
	}))
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "catalog-baseline.toml")
	if err := Fetch(context.Background(), srv.URL, dest, HTTPFetcher{}); err == nil {
		t.Fatal("expected Fetch to reject an invalid catalog")
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Error("no file must be written when the downloaded catalog is invalid")
	}
}

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
	pub, priv, _ := ed25519.GenerateKey(nil)
	sig := ed25519.Sign(priv, []byte(validBaselineTOML))
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
