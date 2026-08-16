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

func (h HTTPFetcher) Fetch(ctx context.Context, url string) ([]byte, error) {
	if err := requireSafeCatalogURL(url); err != nil {
		return nil, err
	}
	c := h.Client
	if c == nil {
		c = http.DefaultClient
	}
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
	return io.ReadAll(resp.Body)
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
	c, err := catalog.Load(data)
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
