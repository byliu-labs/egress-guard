// Package catalogfetch downloads compiled baseline catalogs and installs only
// files that validate under the catalog schema.
package catalogfetch

import (
	"context"
	"fmt"
	"io"
	"net"
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
		return fmt.Errorf("catalogfetch: download signature %s: %w", sigURL, err)
	}
	if err := catalogsig.Verify(data, sig, pub); err != nil {
		return fmt.Errorf("catalogfetch: %w", err)
	}
	return installValid(data, destPath)
}

func installValid(data []byte, destPath string) error {
	c, err := catalog.LoadLayer(data, "baseline")
	if err != nil {
		return fmt.Errorf("catalogfetch: refusing to install invalid catalog: %w", err)
	}
	if c.EntryCount() == 0 {
		return fmt.Errorf("catalogfetch: refusing to install empty catalog")
	}
	if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
		return fmt.Errorf("catalogfetch: mkdir: %w", err)
	}
	tmp := destPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("catalogfetch: write temp: %w", err)
	}
	if err := os.Rename(tmp, destPath); err != nil {
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
	if u.Scheme == "http" && isLoopbackHost(u.Hostname()) {
		return nil
	}
	return fmt.Errorf("catalogfetch: %s is not allowed for remote catalog fetch; use https", u.Scheme)
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
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
		if err := requireSafeCatalogURL(req.URL.String()); err != nil {
			return fmt.Errorf("catalogfetch: refusing redirect: %w", err)
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
