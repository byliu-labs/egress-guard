package explain_test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/explain"
)

type fakeTransport struct {
	body          string
	bodyReader    io.ReadCloser
	statusCode    int
	calls         int
	lastHost      string
	authorization string
}

func (f *fakeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	f.calls++
	f.lastHost = req.URL.Host
	f.authorization = req.Header.Get("Authorization")
	status := f.statusCode
	if status == 0 {
		status = http.StatusOK
	}
	body := f.bodyReader
	if body == nil {
		body = io.NopCloser(strings.NewReader(f.body))
	}
	return &http.Response{
		StatusCode: status,
		Body:       body,
		Header:     make(http.Header),
	}, nil
}

func TestHTTPExplainer_Explain_HappyPath(t *testing.T) {
	body := `{"choices":[{"message":{"role":"assistant","content":"{\"explanation\":\"Looks like an auto-updater.\",\"confidence\":\"medium\",\"evidence\":\"common bundle id pattern\"}"}}]}`
	ft := &fakeTransport{body: body}
	cfg := explain.Config{Endpoint: "https://configured.test/v1/chat/completions", APIKey: "test-key", Model: "test-model"}
	ex := explain.NewHTTPExplainer(cfg, ft)

	got, err := ex.Explain(context.Background(), catalog.Identity{ExeBasename: "updater"}, "updates.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ft.calls != 1 {
		t.Fatalf("expected exactly one HTTP call, got %d", ft.calls)
	}
	if ft.lastHost != "configured.test" {
		t.Fatalf("expected call to configured.test, got %s", ft.lastHost)
	}
	if ft.authorization != "Bearer test-key" {
		t.Fatalf("expected bearer auth from configured API key, got %q", ft.authorization)
	}
	if got.Text == "" || !got.ModelOpinion {
		t.Fatalf("expected a populated model-opinion Explanation, got %+v", got)
	}
}

func TestHTTPExplainer_Explain_APIModeRejectsPlainHTTP(t *testing.T) {
	body := `{"choices":[{"message":{"role":"assistant","content":"{\"explanation\":\"Looks like an auto-updater.\",\"confidence\":\"medium\",\"evidence\":\"common bundle id pattern\"}"}}]}`
	ft := &fakeTransport{body: body}
	cfg := explain.Config{Endpoint: "http://configured.test/v1/chat/completions", APIKey: "test-key"}
	ex := explain.NewHTTPExplainer(cfg, ft)

	_, err := ex.Explain(context.Background(), catalog.Identity{}, "updates.example.com")
	if err == nil {
		t.Fatal("API mode must reject plaintext HTTP before attaching bearer credentials")
	}
	if ft.calls != 0 {
		t.Fatalf("insecure API-mode endpoint must fail before any HTTP call, got %d calls", ft.calls)
	}
}

func TestHTTPExplainer_Explain_LocalModeSkipsAuthorization(t *testing.T) {
	body := `{"choices":[{"message":{"role":"assistant","content":"{\"explanation\":\"Looks like an auto-updater.\",\"confidence\":\"medium\",\"evidence\":\"common bundle id pattern\"}"}}]}`
	ft := &fakeTransport{body: body}
	cfg := explain.Config{Endpoint: "http://localhost:11434/v1/chat/completions", LocalOnly: true}
	ex := explain.NewHTTPExplainer(cfg, ft)

	if _, err := ex.Explain(context.Background(), catalog.Identity{}, "updates.example.com"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ft.authorization != "" {
		t.Fatalf("local mode must not send Authorization, got %q", ft.authorization)
	}
}

func TestHTTPExplainer_Explain_NonOKStatusIsAnError(t *testing.T) {
	ft := &fakeTransport{body: `{"error":"rate limited"}`, statusCode: http.StatusTooManyRequests}
	cfg := explain.Config{Endpoint: "https://configured.test/v1/chat/completions", APIKey: "test-key"}
	ex := explain.NewHTTPExplainer(cfg, ft)

	_, err := ex.Explain(context.Background(), catalog.Identity{}, "example.com")
	if err == nil {
		t.Fatal("expected a non-200 status to be an error")
	}
}

func TestHTTPExplainer_Explain_ResponseBodyTooLargeIsAnError(t *testing.T) {
	body := &countingReadCloser{Reader: strings.NewReader(strings.Repeat("x", 2<<20))}
	ft := &fakeTransport{bodyReader: body}
	cfg := explain.Config{Endpoint: "https://configured.test/v1/chat/completions", APIKey: "test-key"}
	ex := explain.NewHTTPExplainer(cfg, ft)

	_, err := ex.Explain(context.Background(), catalog.Identity{}, "example.com")
	if err == nil {
		t.Fatal("expected oversized response body to be rejected")
	}
	if body.n >= 2<<20 {
		t.Fatalf("response reader was consumed without a cap: read %d bytes", body.n)
	}
}

type countingReadCloser struct {
	*strings.Reader
	n int64
}

func (c *countingReadCloser) Read(p []byte) (int, error) {
	n, err := c.Reader.Read(p)
	c.n += int64(n)
	return n, err
}

func (c *countingReadCloser) Close() error { return nil }
