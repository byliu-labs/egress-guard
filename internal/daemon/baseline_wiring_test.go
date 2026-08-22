package daemon

import (
	"testing"

	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/decisionlog"
	"github.com/byliu-labs/egress-guard/internal/drift"
	"github.com/byliu-labs/egress-guard/internal/procid"
	"github.com/byliu-labs/egress-guard/internal/signature"
)

func TestClassifyCompletedFlowScoresCapturedConcurrency(t *testing.T) {
	entries := []decisionlog.Entry{
		{Kind: decisionlog.KindDecision, ConnID: "old-1", Timestamp: "2026-08-17T14:00:00Z", Decision: decisionlog.DecisionAllow, Exe: "/usr/bin/curl", Host: "api.example.com"},
		{Kind: decisionlog.KindFlow, ConnID: "old-1", BytesUp: 10, BytesDown: 10, DurationMS: 10},
		{Kind: decisionlog.KindDecision, ConnID: "old-2", Timestamp: "2026-08-18T14:00:00Z", Decision: decisionlog.DecisionAllow, Exe: "/usr/bin/curl", Host: "api.example.com"},
		{Kind: decisionlog.KindFlow, ConnID: "old-2", BytesUp: 10, BytesDown: 10, DurationMS: 10},
	}
	d := newDaemonForBaselineTest()
	d.SetBaseline(drift.BuildBaseline(&catalog.Catalog{}, entries))
	decision := decisionlog.Entry{ConnID: "new", Timestamp: "2026-08-19T14:00:00Z", Exe: "/usr/bin/curl", Host: "api.example.com"}
	flow := decisionlog.Entry{ConnID: "new", BytesUp: 10, BytesDown: 10, DurationMS: 10}
	busy := d.classifyCompletedFlow(decision, flow, 9)
	quiet := d.classifyCompletedFlow(decision, flow, 0)
	if !busy.Score.Scored || !quiet.Score.Scored {
		t.Fatalf("scores = %+v / %+v, want both scored", busy.Score, quiet.Score)
	}
	// Comparative, so the dimension being hard-wired to zero fails here. The
	// bytes/hour/inter-arrival dimensions already make the distance non-zero,
	// so a bare "Distance != 0" assertion proves only that scoring ran.
	if busy.Score.Distance <= quiet.Score.Distance {
		t.Fatalf("captured concurrency did not reach the score: busy=%v quiet=%v",
			busy.Score.Distance, quiet.Score.Distance)
	}
}

// TestClassifyDrift_UsesStoredBaseline proves the baseline stored on a daemon is
// what classifyDrift consults: a pair the baseline learned as normal classifies
// as known, not drift. This is the behavioral confirmation that seam #2 is live.
func TestClassifyDrift_UsesStoredBaseline(t *testing.T) {
	b := drift.BuildBaseline(&catalog.Catalog{}, []decisionlog.Entry{
		{Timestamp: "2026-07-01T10:00:00Z", Decision: decisionlog.DecisionAllow, Exe: "/usr/bin/curl", Host: "api.example.com"},
		{Timestamp: "2026-07-02T10:00:00Z", Decision: decisionlog.DecisionAllow, Exe: "/usr/bin/curl", Host: "api.example.com"},
	})
	d := newDaemonForBaselineTest()
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
	d := newDaemonForBaselineTest()
	d.SetBaseline(b)

	ev := d.classifyDrift("github.com",
		procid.ProcInfo{Exe: "/usr/bin/git", PID: 1},
		signature.SignedIdentity{},
		catalog.Identity{ExeBasename: "git", ExeSHA256: "abc123"})
	if ev.Class != drift.ClassKnown {
		t.Fatalf("expected exe_sha256-keyed baseline to classify known, got class=%q reason=%q", ev.Class, ev.Reason)
	}
}

func TestClassifyDriftMarksFlowlessHandshakeAsUnscored(t *testing.T) {
	b := drift.BuildBaseline(&catalog.Catalog{}, []decisionlog.Entry{
		{Timestamp: "2026-07-01T10:00:00Z", Decision: decisionlog.DecisionAllow, Exe: "/usr/bin/git", Host: "github.com"},
		{Timestamp: "2026-07-02T10:00:00Z", Decision: decisionlog.DecisionAllow, Exe: "/usr/bin/git", Host: "github.com"},
	})
	d := newDaemonForBaselineTest()
	d.SetBaseline(b)
	ev := d.classifyDrift("github.com", procid.ProcInfo{Exe: "/usr/bin/git", PID: 1}, signature.SignedIdentity{}, catalog.Identity{ExeBasename: "git"})
	if ev.Score.Scored || ev.Score.Distance != 0 {
		t.Fatalf("handshake score = %+v, want explicit unscored state", ev.Score)
	}
}

func TestClassifyDrift_PreservesRuntimeExePathForRatification(t *testing.T) {
	d := newDaemonForBaselineTest()
	d.SetBaseline(drift.BuildBaseline(&catalog.Catalog{}, nil))
	fullID := catalog.Identity{
		ExeBasename: "node",
		ExePath:     "/opt/homebrew/Cellar/node/25.8.2/bin/node",
		ExeSHA256:   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}

	ev := d.classifyDrift("registry.npmjs.org",
		procid.ProcInfo{Exe: "/opt/homebrew/bin/node", PID: 1},
		signature.SignedIdentity{},
		fullID)

	if ev.Identity != fullID {
		t.Fatalf("Drift identity = %+v, want runtime identity %+v", ev.Identity, fullID)
	}
}
