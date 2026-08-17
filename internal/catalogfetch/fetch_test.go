package catalogfetch

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

const validIssuedBaselineTOML = "issued_at = \"2026-08-16T00:00:00Z\"\n" + validBaselineTOML

func TestFetchVerified_RejectsBadSignature(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	mux := http.NewServeMux()
	mux.HandleFunc("/c", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(validIssuedBaselineTOML))
	})
	mux.HandleFunc("/c.sig", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not a real signature"))
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "catalog-baseline.toml")
	err := FetchVerified(context.Background(), srv.URL+"/c", srv.URL+"/c.sig", dest, HTTPFetcher{Client: srv.Client()}, pub)
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
	sig, err := catalogsig.Sign([]byte(validIssuedBaselineTOML), priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/c", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(validIssuedBaselineTOML))
	})
	mux.HandleFunc("/c.sig", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(sig)
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "catalog-baseline.toml")
	if err := FetchVerified(context.Background(), srv.URL+"/c", srv.URL+"/c.sig", dest, HTTPFetcher{Client: srv.Client()}, pub); err != nil {
		t.Fatalf("FetchVerified: %v", err)
	}
	if _, err := catalog.LoadFile(dest); err != nil {
		t.Fatalf("installed signed catalog is invalid: %v", err)
	}
}

func TestFetchVerified_RejectsSignedBaselineWithLayerEscalation(t *testing.T) {
	pub, priv, err := catalogsig.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	body := []byte(strings.Replace(validIssuedBaselineTOML, `layer = "baseline"`, `layer = "user"`, 1))
	sig, err := catalogsig.Sign(body, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/c", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	})
	mux.HandleFunc("/c.sig", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(sig)
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "catalog-baseline.toml")
	if err := FetchVerified(context.Background(), srv.URL+"/c", srv.URL+"/c.sig", dest, HTTPFetcher{Client: srv.Client()}, pub); err == nil {
		t.Fatal("FetchVerified accepted a signed baseline catalog containing layer=user")
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatal("no file must be written when baseline layer validation fails")
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
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "catalog-baseline.toml")
	if err := os.WriteFile(dest, []byte(validIssuedBaselineTOML), 0o644); err != nil {
		t.Fatalf("seed existing catalog: %v", err)
	}
	err = FetchVerified(context.Background(), srv.URL+"/c", srv.URL+"/c.sig", dest, HTTPFetcher{Client: srv.Client()}, pub)
	if err == nil {
		t.Fatal("expected FetchVerified to reject a signed-but-empty catalog")
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read preserved catalog: %v", err)
	}
	if string(got) != validIssuedBaselineTOML {
		t.Fatalf("existing catalog was replaced by empty body:\n%s", got)
	}
}

func TestHTTPFetcher_RejectsPlainRemoteHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(validIssuedBaselineTOML))
	}))
	defer srv.Close()

	_, err := (HTTPFetcher{}).Fetch(context.Background(), srv.URL+"/catalog.toml")
	if err == nil {
		t.Fatal("expected plain HTTP to be rejected before download")
	}
	if !strings.Contains(err.Error(), "https") {
		t.Fatalf("error %q does not tell the user https is required", err)
	}
}

func TestHTTPFetcher_RejectsOversizedBody(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(make([]byte, MaxCatalogBytes+1))
	}))
	defer srv.Close()

	_, err := (HTTPFetcher{Client: srv.Client()}).Fetch(context.Background(), srv.URL+"/catalog.toml")
	if err == nil {
		t.Fatal("oversized body accepted")
	}
}

func TestHTTPFetcher_RejectsCrossHostRedirect(t *testing.T) {
	final := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(validBaselineTOML))
	}))
	defer final.Close()
	hop := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, final.URL+"/catalog.toml", http.StatusFound)
	}))
	defer hop.Close()

	_, err := (HTTPFetcher{Client: hop.Client()}).Fetch(context.Background(), hop.URL+"/catalog.toml")
	if err == nil {
		t.Fatal("cross-host redirect followed")
	}
}

func TestInstall_RefusesReplayOfOlderCatalog(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "catalog-baseline.toml")
	newer := []byte(validIssuedBaselineTOML)
	older := []byte("issued_at = \"2026-08-09T00:00:00Z\"\n" + strings.Replace(validBaselineTOML, "pypi.org", "evil.example", 1))
	if err := os.WriteFile(dest, newer, 0o644); err != nil {
		t.Fatalf("seed newer catalog: %v", err)
	}
	if err := installValid(older, dest); err == nil {
		t.Fatal("older catalog installed over a newer one")
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read preserved catalog: %v", err)
	}
	if string(got) != string(newer) {
		t.Fatal("existing catalog was replaced by replayed bytes")
	}
}

func TestInstall_CurrentCatalogIsNoop(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "catalog-baseline.toml")
	current := []byte(validIssuedBaselineTOML)
	if err := os.WriteFile(dest, current, 0o644); err != nil {
		t.Fatalf("seed current catalog: %v", err)
	}

	if err := installValid(current, dest); err != nil {
		t.Fatalf("current catalog reinstall should be a no-op success: %v", err)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read current catalog: %v", err)
	}
	if string(got) != string(current) {
		t.Fatal("current catalog reinstall changed the installed bytes")
	}
}

func TestInstall_RefusesDifferentCatalogWithSameIssuedAt(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "catalog-baseline.toml")
	current := []byte(validIssuedBaselineTOML)
	changed := []byte(strings.Replace(validIssuedBaselineTOML, "pypi.org", "evil.example", 1))
	if err := os.WriteFile(dest, current, 0o644); err != nil {
		t.Fatalf("seed current catalog: %v", err)
	}

	if err := installValid(changed, dest); err == nil {
		t.Fatal("same issued_at with different bytes must not replace the installed catalog")
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read preserved catalog: %v", err)
	}
	if string(got) != string(current) {
		t.Fatal("same-issued-at catalog changed the installed bytes")
	}
}
