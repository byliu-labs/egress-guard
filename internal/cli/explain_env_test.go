package cli

import (
	"testing"
)

func TestBuildExplainer_UnsetIsNilAndSilent(t *testing.T) {
	t.Setenv("EGRESS_GUARD_EXPLAIN_ENDPOINT", "")
	var warned bool
	ex := buildExplainer(func(string, ...any) { warned = true })
	if ex != nil {
		t.Fatal("no endpoint set → explainer must be nil")
	}
	if warned {
		t.Fatal("unconfigured explainer is the normal case → must not warn")
	}
}

func TestBuildExplainer_MisconfiguredWarnsAndIsNil(t *testing.T) {
	// Endpoint set but non-https in API mode (no LOCAL flag, no key) → invalid.
	t.Setenv("EGRESS_GUARD_EXPLAIN_ENDPOINT", "http://insecure.example.com/v1")
	t.Setenv("EGRESS_GUARD_EXPLAIN_API_KEY", "")
	t.Setenv("EGRESS_GUARD_EXPLAIN_LOCAL", "")
	var warned bool
	ex := buildExplainer(func(string, ...any) { warned = true })
	if ex != nil {
		t.Fatal("misconfigured explainer must not be returned")
	}
	if !warned {
		t.Fatal("misconfigured explainer must warn the operator")
	}
}

func TestBuildExplainer_ValidReturnsExplainer(t *testing.T) {
	t.Setenv("EGRESS_GUARD_EXPLAIN_ENDPOINT", "https://api.example.com/v1/chat")
	t.Setenv("EGRESS_GUARD_EXPLAIN_API_KEY", "test-key")
	t.Setenv("EGRESS_GUARD_EXPLAIN_LOCAL", "")
	var warned bool
	ex := buildExplainer(func(string, ...any) { warned = true })
	if ex == nil {
		t.Fatal("valid https endpoint + key → explainer must be non-nil")
	}
	if warned {
		t.Fatal("valid config must not warn")
	}
}
