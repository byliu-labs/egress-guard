// Package explain defines model-generated egress explanations.
//
// The explainer implementation is intentionally out of scope for the
// drift-prompt wiring. This package owns only the data shape consumed by the
// prompt renderer so model opinions can be labeled separately from catalog
// facts.
package explain

import (
	"context"

	"github.com/byliu-labs/egress-guard/internal/catalog"
)

// Explanation is advisory context from a model, never a catalog fact.
type Explanation struct {
	Text         string
	Confidence   catalog.Confidence
	Evidence     string
	Never        []string
	ModelOpinion bool
}

// New builds an Explanation with ModelOpinion pinned to true.
func New(text string, confidence catalog.Confidence, evidence string, never []string) Explanation {
	return Explanation{
		Text:         text,
		Confidence:   confidence,
		Evidence:     evidence,
		Never:        never,
		ModelOpinion: true,
	}
}

// Explainer produces a model opinion for an unknown identity talking to host.
// Implementations must remain cold-path only, never admission-path policy.
type Explainer interface {
	Explain(ctx context.Context, id catalog.Identity, host string) (Explanation, error)
}
