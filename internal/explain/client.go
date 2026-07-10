package explain

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/byliu-labs/egress-guard/internal/catalog"
)

const maxResponseBytes = 1 << 20

// HTTPExplainer POSTs to cfg.Endpoint through an injectable transport.
type HTTPExplainer struct {
	cfg    Config
	client *http.Client
}

// NewHTTPExplainer builds a live explainer against cfg. Tests pass a fake
// transport so no test makes a real network call.
func NewHTTPExplainer(cfg Config, transport http.RoundTripper) *HTTPExplainer {
	if transport == nil {
		transport = http.DefaultTransport
	}
	return &HTTPExplainer{
		cfg: cfg,
		client: &http.Client{
			Transport:     transport,
			Timeout:       15 * time.Second,
			CheckRedirect: refuseCrossHostRedirect(cfg.Endpoint),
		},
	}
}

// Explain implements Explainer. It is a cold-path advisory call, not an
// admission-path decision.
func (h *HTTPExplainer) Explain(ctx context.Context, id catalog.Identity, host string) (Explanation, error) {
	if err := validateEndpointSecurity(h.cfg); err != nil {
		return Explanation{}, err
	}
	body, err := buildRequestBody(h.cfg, id, host)
	if err != nil {
		return Explanation{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.cfg.Endpoint, bytes.NewReader(body))
	if err != nil {
		return Explanation{}, fmt.Errorf("explain: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if !h.cfg.LocalOnly {
		req.Header.Set("Authorization", "Bearer "+h.cfg.APIKey)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return Explanation{}, fmt.Errorf("explain: request to %s: %w", h.cfg.Endpoint, err)
	}
	defer resp.Body.Close()
	raw, err := readLimitedResponse(resp.Body)
	if err != nil {
		return Explanation{}, fmt.Errorf("explain: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return Explanation{}, fmt.Errorf("explain: endpoint returned status %d: %s", resp.StatusCode, string(raw))
	}
	return parseResponseBody(raw)
}

func readLimitedResponse(r io.Reader) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(r, maxResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxResponseBytes {
		return nil, fmt.Errorf("response exceeds %d bytes", maxResponseBytes)
	}
	return raw, nil
}

func refuseCrossHostRedirect(endpoint string) func(req *http.Request, via []*http.Request) error {
	allowed, err := url.Parse(endpoint)
	if err != nil {
		return func(req *http.Request, via []*http.Request) error {
			return fmt.Errorf("explain: redirect refused: configured endpoint %q is not a valid URL", endpoint)
		}
	}
	return func(req *http.Request, via []*http.Request) error {
		if req.URL.Host != allowed.Host {
			return fmt.Errorf("explain: refusing redirect from %s to %s", allowed.Host, req.URL.Host)
		}
		return nil
	}
}
