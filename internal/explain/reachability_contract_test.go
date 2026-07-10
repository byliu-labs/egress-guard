package explain_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/explain"
)

type singleHostTransport struct {
	allowedHost string
}

func (s *singleHostTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host != s.allowedHost {
		return nil, fmt.Errorf("reachability contract violated: dialed %q, only %q is permitted", req.URL.Host, s.allowedHost)
	}
	body := `{"choices":[{"message":{"role":"assistant","content":"{\"explanation\":\"ok\",\"confidence\":\"high\",\"evidence\":\"test\"}"}}]}`
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
}

func TestHTTPExplainer_OnlyReachesConfiguredEndpoint(t *testing.T) {
	transport := &singleHostTransport{allowedHost: "configured.test"}
	cfg := explain.Config{Endpoint: "https://configured.test/v1/chat/completions", APIKey: "test-key"}
	ex := explain.NewHTTPExplainer(cfg, transport)

	if _, err := ex.Explain(context.Background(), catalog.Identity{ExeBasename: "updater"}, "some-destination.example.com"); err != nil {
		t.Fatalf("call to the configured endpoint must succeed, got: %v", err)
	}
}

func TestHTTPExplainer_MisconfiguredEndpointFailsLoudly(t *testing.T) {
	transport := &singleHostTransport{allowedHost: "configured.test"}
	cfg := explain.Config{Endpoint: "https://attacker.test/v1/chat/completions", APIKey: "test-key"}
	ex := explain.NewHTTPExplainer(cfg, transport)

	_, err := ex.Explain(context.Background(), catalog.Identity{}, "example.com")
	if err == nil || !strings.Contains(err.Error(), "reachability contract violated") {
		t.Fatalf("expected a reachability-contract error, got: %v", err)
	}
}
