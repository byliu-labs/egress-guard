package daemon

import (
	"testing"

	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/decisionlog"
	"github.com/byliu-labs/egress-guard/internal/drift"
	"github.com/byliu-labs/egress-guard/internal/procid"
	"github.com/byliu-labs/egress-guard/internal/signature"
)

// TestClassifyDrift_UsesStoredBaseline proves the baseline stored on a daemon is
// what classifyDrift consults: a pair the baseline learned as normal classifies
// as known, not drift. This is the behavioral confirmation that seam #2 is live.
func TestClassifyDrift_UsesStoredBaseline(t *testing.T) {
	b := drift.BuildBaseline(&catalog.Catalog{}, []decisionlog.Entry{
		{Timestamp: "2026-07-01T10:00:00Z", Decision: decisionlog.DecisionAllow, Exe: "/usr/bin/curl", Host: "api.example.com"},
		{Timestamp: "2026-07-02T10:00:00Z", Decision: decisionlog.DecisionAllow, Exe: "/usr/bin/curl", Host: "api.example.com"},
	})
	d := &Daemon{}
	d.SetBaseline(b)

	ev := d.classifyDrift("api.example.com",
		procid.ProcInfo{Exe: "/usr/bin/curl", PID: 1},
		signature.SignedIdentity{},
		catalog.Identity{ExeBasename: "curl"})
	if ev.Class != drift.ClassKnown {
		t.Fatalf("expected stored baseline to classify learned pair known, got class=%q reason=%q", ev.Class, ev.Reason)
	}
}

func TestClassifyDrift_UsesRuntimeExeSHA256ForBaselineKey(t *testing.T) {
	b := drift.BuildBaseline(&catalog.Catalog{}, []decisionlog.Entry{
		{Timestamp: "2026-07-01T10:00:00Z", Decision: decisionlog.DecisionAllow, Exe: "/usr/bin/git", ExeSHA256: "abc123", Host: "github.com"},
		{Timestamp: "2026-07-02T10:00:00Z", Decision: decisionlog.DecisionAllow, Exe: "/usr/bin/git", ExeSHA256: "abc123", Host: "github.com"},
	})
	d := &Daemon{}
	d.SetBaseline(b)

	ev := d.classifyDrift("github.com",
		procid.ProcInfo{Exe: "/usr/bin/git", PID: 1},
		signature.SignedIdentity{},
		catalog.Identity{ExeBasename: "git", ExeSHA256: "abc123"})
	if ev.Class != drift.ClassKnown {
		t.Fatalf("expected exe_sha256-keyed baseline to classify known, got class=%q reason=%q", ev.Class, ev.Reason)
	}
}
