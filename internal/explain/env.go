package explain

import (
	"context"

	"github.com/byliu-labs/egress-guard/internal/catalog"
)

// Logger is the minimal shape needed to surface background explainer failures.
type Logger interface {
	Errorf(format string, args ...any)
}

// FromEnv builds a live Explainer from environment configuration.
func FromEnv() (Explainer, error) {
	cfg, err := ConfigFromEnv()
	if err != nil {
		return nil, err
	}
	return NewHTTPExplainer(cfg, nil), nil
}

// TryExplain returns nil on any explainer absence or failure. That keeps the
// explainer strictly additive: catalog-only prompting remains valid.
func TryExplain(ctx context.Context, ex Explainer, id catalog.Identity, host string, logger Logger) *Explanation {
	if ex == nil {
		return nil
	}
	exp, err := ex.Explain(ctx, id, host)
	if err != nil {
		if logger != nil {
			logger.Errorf("explain: Explain(%s, %q) failed, continuing without a model opinion: %v", id.ExeBasename, host, err)
		}
		return nil
	}
	return &exp
}
