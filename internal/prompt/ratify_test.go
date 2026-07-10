package prompt

import (
	"context"
	"errors"
	"testing"

	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/drift"
	"github.com/byliu-labs/egress-guard/internal/explain"
	"github.com/byliu-labs/egress-guard/internal/procid"
)

func TestCatalogEntryFor_AllowPopulatesExpectedDestinations(t *testing.T) {
	req := Request{
		Host:   "api.driftapp-telemetry.io",
		Proc:   procid.ProcInfo{Comm: "driftapp"},
		RegDom: "driftapp-telemetry.io",
		Drift:  drift.Event{Identity: catalog.Identity{ExeBasename: "driftapp", TeamID: "TEAMX"}},
	}
	e := catalogEntryFor(req, true)
	if len(e.ExpectedDestinations) != 1 || e.ExpectedDestinations[0].Host != "api.driftapp-telemetry.io" {
		t.Errorf("ExpectedDestinations = %+v, want one entry for api.driftapp-telemetry.io", e.ExpectedDestinations)
	}
	if len(e.Never) != 0 {
		t.Errorf("Never = %v, want empty on allow", e.Never)
	}
	if e.Confidence != catalog.ConfidenceHigh {
		t.Errorf("Confidence = %v, want ConfidenceHigh", e.Confidence)
	}
	if e.Layer != "user" {
		t.Errorf("Layer = %q, want user", e.Layer)
	}
	wantID := catalog.Identity{ExeBasename: "driftapp", TeamID: "TEAMX"}
	if e.Identity != wantID {
		t.Errorf("Identity = %+v, want %+v", e.Identity, wantID)
	}
	if e.Evidence == "" {
		t.Error("Evidence must be non-empty")
	}
}

func TestCatalogEntryFor_DenyPopulatesNever(t *testing.T) {
	req := Request{
		Host:   "cdn.bad.example",
		Proc:   procid.ProcInfo{Comm: "badapp"},
		RegDom: "bad.example",
		Drift:  drift.Event{Identity: catalog.Identity{ExeBasename: "badapp", TeamID: "TEAMX"}},
	}
	e := catalogEntryFor(req, false)
	if len(e.Never) != 1 || e.Never[0] != "cdn.bad.example" {
		t.Errorf("Never = %v, want [cdn.bad.example]", e.Never)
	}
	if len(e.ExpectedDestinations) != 0 {
		t.Errorf("ExpectedDestinations = %+v, want empty on deny", e.ExpectedDestinations)
	}
}

func TestCatalogEntryFor_IgnoresOpinion(t *testing.T) {
	base := Request{
		Host:   "api.driftapp-telemetry.io",
		Proc:   procid.ProcInfo{Comm: "driftapp"},
		RegDom: "driftapp-telemetry.io",
		Drift:  drift.Event{Identity: catalog.Identity{ExeBasename: "driftapp", TeamID: "TEAMX"}},
	}
	withOpinion := base
	withOpinion.Opinion = &explain.Explanation{
		Text: "a low-confidence guess", Confidence: catalog.ConfidenceMedium, Evidence: "weak signal",
	}

	e1 := catalogEntryFor(base, true)
	e2 := catalogEntryFor(withOpinion, true)
	if e1.Confidence != e2.Confidence {
		t.Errorf("Confidence changed with Opinion present: %v vs %v", e1.Confidence, e2.Confidence)
	}
	if e2.Confidence != catalog.ConfidenceHigh {
		t.Errorf("Confidence = %v, want ConfidenceHigh regardless of Opinion.Confidence=%v", e2.Confidence, withOpinion.Opinion.Confidence)
	}
}

func TestCatalogEntryFor_UnsignedIdentityUsesMediumConfidence(t *testing.T) {
	req := Request{
		Host:   "api.localtool.example",
		Proc:   procid.ProcInfo{Comm: "localtool"},
		RegDom: "localtool.example",
		Drift:  drift.Event{Identity: catalog.Identity{ExeBasename: "localtool"}},
	}
	e := catalogEntryFor(req, true)
	if e.Confidence != catalog.ConfidenceMedium {
		t.Errorf("Confidence = %v, want ConfidenceMedium for identity without signature anchor", e.Confidence)
	}
	if err := (&catalog.Catalog{}).Add(e); err != nil {
		t.Fatalf("catalog.Add(unsigned ratification) = %v, want valid medium-confidence entry", err)
	}
}

type recordingRatifyWriter struct {
	calls int
	lastE catalog.Entry
	err   error
}

func (r *recordingRatifyWriter) Ratify(e catalog.Entry) error {
	r.calls++
	r.lastE = e
	return r.err
}

func TestDecide_AllowAlwaysWithRatifyWriter_SkipsLegacyAlwaysWriter(t *testing.T) {
	rw := &recordingRatifyWriter{}
	legacy := &recordingWriter{}
	d := New(Options{Notifier: &StaticNotifier{A: ActionAllowAlways}, RatifyWriter: rw, AlwaysWriter: legacy})
	got := d.Decide(context.Background(), Request{
		Proc: procid.ProcInfo{Comm: "driftapp"}, Host: "api.driftapp.io", RegDom: "driftapp.io",
		Drift: drift.Event{Identity: catalog.Identity{ExeBasename: "driftapp", TeamID: "TEAMX"}},
	})
	if got != Allow {
		t.Errorf("Decide() = %v, want Allow", got)
	}
	if rw.calls != 1 {
		t.Fatalf("RatifyWriter.Ratify calls = %d, want 1", rw.calls)
	}
	if len(rw.lastE.ExpectedDestinations) != 1 || rw.lastE.ExpectedDestinations[0].Host != "api.driftapp.io" {
		t.Errorf("Ratify called with %+v, want ExpectedDestinations=[api.driftapp.io]", rw.lastE)
	}
	if legacy.allowCalls != 0 {
		t.Errorf("legacy AlwaysWriter.AddAllow calls = %d, want 0", legacy.allowCalls)
	}
}

func TestDecide_DenyAlwaysWithRatifyWriter_WritesNever(t *testing.T) {
	rw := &recordingRatifyWriter{}
	d := New(Options{Notifier: &StaticNotifier{A: ActionDenyAlways}, RatifyWriter: rw})
	d.Decide(context.Background(), Request{
		Proc: procid.ProcInfo{Comm: "badapp"}, Host: "api.bad.example", RegDom: "bad.example",
		Drift: drift.Event{Identity: catalog.Identity{ExeBasename: "badapp", TeamID: "TEAMX"}},
	})
	if rw.calls != 1 {
		t.Fatalf("Ratify calls = %d, want 1", rw.calls)
	}
	if len(rw.lastE.Never) != 1 || rw.lastE.Never[0] != "api.bad.example" {
		t.Errorf("Ratify called with %+v, want Never=[api.bad.example]", rw.lastE)
	}
}

func TestDecide_RatifyWriterErrorReachesLogger(t *testing.T) {
	logger := &recordingLogger{}
	rw := &recordingRatifyWriter{err: errors.New("disk full")}
	d := New(Options{Notifier: &StaticNotifier{A: ActionAllowAlways}, RatifyWriter: rw, Logger: logger})
	d.Decide(context.Background(), Request{Proc: procid.ProcInfo{Comm: "x"}, Host: "x.com", RegDom: "x.com"})
	msgs := logger.snapshot()
	if len(msgs) != 1 || !contains(msgs[0], "Ratify") || !contains(msgs[0], "disk full") {
		t.Errorf("logged %v, want one message mentioning Ratify + disk full", msgs)
	}
}

func TestDecide_OpinionAlonePersistsNothingWithoutRatifyAction(t *testing.T) {
	rw := &recordingRatifyWriter{}
	d := New(Options{Notifier: &StaticNotifier{A: ActionAllowOnce}, RatifyWriter: rw})
	got := d.Decide(context.Background(), Request{
		Proc: procid.ProcInfo{Comm: "driftapp"}, Host: "api.driftapp.io", RegDom: "driftapp.io",
		Opinion: &explain.Explanation{Text: "guess", Confidence: catalog.ConfidenceMedium, Evidence: "weak"},
	})
	if got != Allow {
		t.Errorf("Decide() = %v, want Allow", got)
	}
	if rw.calls != 0 {
		t.Errorf("Ratify calls = %d, want 0", rw.calls)
	}
}
