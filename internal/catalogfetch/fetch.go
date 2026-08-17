// Package catalogfetch downloads compiled baseline catalogs and installs only
// files that validate under the catalog schema.
package catalogfetch

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/catalogsig"
)

// Fetcher is the network seam. Production uses HTTPFetcher; tests use
// httptest-backed HTTPFetcher or small fakes in higher-level packages.
type Fetcher interface {
	Fetch(ctx context.Context, url string) ([]byte, error)
}

// HTTPFetcher fetches over HTTP(S). A nil Client uses http.DefaultClient.
type HTTPFetcher struct {
	Client *http.Client
}

const MaxCatalogBytes = 8 << 20

// ErrSignature marks failures where the catalog bytes could not be authenticated.
var ErrSignature = errors.New("catalogfetch: signature error")

func (h HTTPFetcher) Fetch(ctx context.Context, url string) ([]byte, error) {
	if err := requireSafeCatalogURL(url); err != nil {
		return nil, err
	}
	c := secureClient(h.Client)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http %d fetching %s", resp.StatusCode, url)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxCatalogBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxCatalogBytes {
		return nil, fmt.Errorf("catalogfetch: %s exceeds %d bytes", url, MaxCatalogBytes)
	}
	return data, nil
}

// FetchVerified downloads url and its detached signature at sigURL, verifies
// the signature, then installs only if the catalog schema also validates.
func FetchVerified(ctx context.Context, url, sigURL, destPath string, f Fetcher, pub []byte) error {
	data, err := f.Fetch(ctx, url)
	if err != nil {
		return fmt.Errorf("catalogfetch: download %s: %w", url, err)
	}
	sig, err := f.Fetch(ctx, sigURL)
	if err != nil {
		return fmt.Errorf("%w: download signature %s: %v", ErrSignature, sigURL, err)
	}
	if err := catalogsig.Verify(data, sig, pub); err != nil {
		return fmt.Errorf("%w: %v", ErrSignature, err)
	}
	return installValid(data, destPath)
}

func installValid(data []byte, destPath string) error {
	fresh, err := catalog.LoadLayer(data, "baseline")
	if err != nil {
		return fmt.Errorf("catalogfetch: refusing to install invalid catalog: %w", err)
	}
	if fresh.EntryCount() == 0 {
		return fmt.Errorf("catalogfetch: refusing to install empty catalog")
	}
	if _, err := parseIssuedAt(fresh.IssuedAt()); err != nil {
		return fmt.Errorf("catalogfetch: refusing catalog with invalid issued_at %q: %w", fresh.IssuedAt(), err)
	}
	existing, err := catalog.LoadFile(destPath)
	if err == nil {
		existingAt, err := parseIssuedAt(existing.IssuedAt())
		if err == nil {
			freshAt, _ := parseIssuedAt(fresh.IssuedAt())
			if freshAt.Before(existingAt) {
				return fmt.Errorf("catalogfetch: refusing catalog issued %q, older than installed %q",
					fresh.IssuedAt(), existing.IssuedAt())
			}
			if freshAt.Equal(existingAt) {
				existingBytes, err := os.ReadFile(destPath)
				if err != nil {
					return fmt.Errorf("catalogfetch: cannot read existing catalog %s: %w", destPath, err)
				}
				if bytes.Equal(data, existingBytes) {
					return nil
				}
				return fmt.Errorf("catalogfetch: refusing catalog issued %q with different bytes than installed catalog",
					fresh.IssuedAt())
			}
		}
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("catalogfetch: cannot read existing catalog %s: %w", destPath, err)
	}
	if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
		return fmt.Errorf("catalogfetch: mkdir: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(destPath), ".catalog-*")
	if err != nil {
		return fmt.Errorf("catalogfetch: temp file: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("catalogfetch: write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("catalogfetch: sync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("catalogfetch: close temp: %w", err)
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return fmt.Errorf("catalogfetch: chmod temp: %w", err)
	}
	if err := os.Rename(tmp.Name(), destPath); err != nil {
		return fmt.Errorf("catalogfetch: install: %w", err)
	}
	return nil
}

func requireSafeCatalogURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("catalogfetch: parse URL %q: %w", raw, err)
	}
	if u.Scheme == "https" {
		return nil
	}
	return fmt.Errorf("catalogfetch: %s is not allowed for remote catalog fetch; use https", u.Scheme)
}

func secureClient(base *http.Client) *http.Client {
	var c http.Client
	if base != nil {
		c = *base
	}
	if c.Timeout == 0 {
		c.Timeout = 30 * time.Second
	}
	previous := c.CheckRedirect
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" {
			return fmt.Errorf("catalogfetch: refusing redirect to non-https %s", req.URL)
		}
		if len(via) > 0 && req.URL.Host != via[0].URL.Host {
			return fmt.Errorf("catalogfetch: refusing cross-host redirect to %s", req.URL.Host)
		}
		if previous != nil {
			return previous(req, via)
		}
		return nil
	}
	return &c
}

func strictlyNewer(a, b string) bool {
	at, err := parseIssuedAt(a)
	if err != nil {
		return false
	}
	bt, err := parseIssuedAt(b)
	if err != nil {
		return true
	}
	return at.After(bt)
}

func parseIssuedAt(s string) (time.Time, error) {
	return time.Parse(time.RFC3339, s)
}
