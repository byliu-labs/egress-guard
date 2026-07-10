package explain_test

import (
	"context"
	"errors"
	"testing"

	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/explain"
)

type stubExplainer struct {
	exp explain.Explanation
	err error
}

func (s stubExplainer) Explain(ctx context.Context, id catalog.Identity, host string) (explain.Explanation, error) {
	return s.exp, s.err
}

type fakeLogger struct{ msgs []string }

func (f *fakeLogger) Errorf(format string, args ...any) {
	f.msgs = append(f.msgs, format)
}

func TestFromEnv_NotConfiguredIsAdditive(t *testing.T) {
	t.Setenv("EGRESS_GUARD_EXPLAIN_ENDPOINT", "")
	ex, err := explain.FromEnv()
	if !errors.Is(err, explain.ErrNotConfigured) {
		t.Fatalf("want ErrNotConfigured, got %v", err)
	}
	if ex != nil {
		t.Fatal("want a nil Explainer when not configured")
	}
}

func TestTryExplain_NilExplainerReturnsNil(t *testing.T) {
	got := explain.TryExplain(context.Background(), nil, catalog.Identity{ExeBasename: "curl"}, "example.com", nil)
	if got != nil {
		t.Fatal("TryExplain with a nil Explainer must return nil")
	}
}

func TestTryExplain_ErrorIsLoggedNotSwallowedSilently(t *testing.T) {
	stub := stubExplainer{err: errors.New("connection refused")}
	logger := &fakeLogger{}
	got := explain.TryExplain(context.Background(), stub, catalog.Identity{ExeBasename: "updater"}, "example.com", logger)
	if got != nil {
		t.Fatal("a failing Explainer must degrade to nil, not a fabricated Explanation")
	}
	if len(logger.msgs) == 0 {
		t.Fatal("the failure must be logged, not silently swallowed")
	}
}

func TestTryExplain_SuccessReturnsExplanation(t *testing.T) {
	stub := stubExplainer{exp: explain.New("an updater", catalog.ConfidenceHigh, "known vendor", nil)}
	got := explain.TryExplain(context.Background(), stub, catalog.Identity{}, "example.com", nil)
	if got == nil {
		t.Fatal("expected a non-nil Explanation on success")
	}
	if !got.ModelOpinion {
		t.Fatal("returned Explanation must be tagged ModelOpinion")
	}
}
