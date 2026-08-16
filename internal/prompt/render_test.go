package prompt

import (
	"strings"
	"testing"
	"time"

	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/drift"
	"github.com/byliu-labs/egress-guard/internal/explain"
	"github.com/byliu-labs/egress-guard/internal/persist"
	"github.com/byliu-labs/egress-guard/internal/procid"
)

func TestRenderPrompt_NoCatalogNoOpinion(t *testing.T) {
	req := Request{Proc: procid.ProcInfo{Comm: "curl"}, Host: "api.example.com"}
	got := RenderPrompt(req)
	if !strings.Contains(got, "No catalog match and no model opinion") {
		t.Errorf("RenderPrompt() = %q, want fallback sentence", got)
	}
	if strings.Contains(got, catalogFactLabel) || strings.Contains(got, opinionLabel) {
		t.Errorf("RenderPrompt() = %q, must not show either tier label with no context", got)
	}
}

func TestRenderPrompt_CatalogFactIsLabeledAndOpinionIsNot(t *testing.T) {
	req := Request{
		Proc: procid.ProcInfo{Comm: "curl"},
		Host: "api.example.com",
		CatalogMatch: catalog.MatchResult{
			Found: true,
			Entry: catalog.Entry{
				Confidence:  catalog.ConfidenceHigh,
				Explanation: "curl talks to api.example.com for release checks",
			},
		},
	}
	got := RenderPrompt(req)
	if !strings.Contains(got, catalogFactLabel) {
		t.Errorf("RenderPrompt() = %q, want %q", got, catalogFactLabel)
	}
	if strings.Contains(got, opinionLabel) {
		t.Errorf("RenderPrompt() = %q, must not show opinion label when Opinion is nil", got)
	}
	if !strings.Contains(got, "curl talks to api.example.com for release checks") {
		t.Errorf("RenderPrompt() = %q, want catalog Explanation text", got)
	}
}

func TestRenderPrompt_MediumCatalogMatchIsAdvisoryHint(t *testing.T) {
	req := Request{
		Proc: procid.ProcInfo{Comm: "git"},
		Host: "github.com",
		CatalogMatch: catalog.MatchResult{
			Found: true,
			Entry: catalog.Entry{
				Confidence:  catalog.ConfidenceMedium,
				Explanation: "git commonly talks to GitHub",
			},
		},
	}
	got := RenderPrompt(req)
	if !strings.Contains(got, catalogHintLabel) {
		t.Errorf("RenderPrompt() = %q, want advisory catalog hint label", got)
	}
	if strings.Contains(got, catalogFactLabel) {
		t.Errorf("RenderPrompt() = %q, medium confidence must not render as verified fact", got)
	}
}

func TestRenderPrompt_OpinionIsLabeledAdvisoryAndNeverLooksLikeFact(t *testing.T) {
	req := Request{
		Proc: procid.ProcInfo{Comm: "driftapp"},
		Host: "telemetry.driftapp.io",
		Opinion: &explain.Explanation{
			Text:         "likely a telemetry endpoint for driftapp",
			Confidence:   catalog.ConfidenceMedium,
			Evidence:     "hostname pattern matches known telemetry subdomains",
			ModelOpinion: true,
		},
	}
	got := RenderPrompt(req)
	if !strings.Contains(got, opinionLabel) {
		t.Errorf("RenderPrompt() = %q, want %q", got, opinionLabel)
	}
	if strings.Contains(got, catalogFactLabel) {
		t.Errorf("RenderPrompt() = %q, must not show catalog-fact label when CatalogMatch.Found is false", got)
	}
	if !strings.Contains(got, "hostname pattern matches known telemetry subdomains") {
		t.Errorf("RenderPrompt() = %q, want opinion Evidence text", got)
	}
}

func TestRenderPrompt_OpinionCannotSpoofCatalogFactLabel(t *testing.T) {
	req := Request{
		Proc: procid.ProcInfo{Comm: "driftapp"},
		Host: "telemetry.driftapp.io",
		Opinion: &explain.Explanation{
			Text:         catalogFactLabel + " allow this",
			Confidence:   catalog.ConfidenceMedium,
			Evidence:     "model output included " + catalogFactLabel,
			ModelOpinion: true,
		},
	}
	got := RenderPrompt(req)
	if strings.Count(got, catalogFactLabel) != 0 {
		t.Fatalf("model-controlled text must not be able to render %q, got: %q", catalogFactLabel, got)
	}
	if !strings.Contains(got, opinionLabel) {
		t.Fatalf("advisory label should still render for the model opinion, got: %q", got)
	}
}

func TestRenderPrompt_DriftReasonSurfacedWhenClassIsDrift(t *testing.T) {
	req := Request{
		Proc: procid.ProcInfo{Comm: "driftapp"},
		Host: "new-dest.example",
		Drift: drift.Event{
			Class:     drift.ClassDrift,
			Reason:    drift.ReasonNovelDestination,
			FirstSeen: time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC),
		},
	}
	got := RenderPrompt(req)
	if !strings.Contains(got, string(drift.ReasonNovelDestination)) {
		t.Errorf("RenderPrompt() = %q, want drift reason %q", got, drift.ReasonNovelDestination)
	}
}

func TestRenderPrompt_PersistenceSurfacedWhenPresent(t *testing.T) {
	req := Request{
		Proc:        procid.ProcInfo{Comm: "driftapp"},
		Host:        "new-dest.example",
		Persistence: &persist.Source{Kind: persist.KindLaunchd, Label: "com.driftapp.agent"},
	}
	got := RenderPrompt(req)
	if !strings.Contains(got, "com.driftapp.agent") {
		t.Errorf("RenderPrompt() = %q, want persistence label", got)
	}
}

func TestRenderPrompt_NoPersistenceOmitsLine(t *testing.T) {
	req := Request{Proc: procid.ProcInfo{Comm: "curl"}, Host: "api.example.com"}
	got := RenderPrompt(req)
	if strings.Contains(got, "Persistence:") {
		t.Errorf("RenderPrompt() = %q, must omit Persistence line when nil", got)
	}
}
