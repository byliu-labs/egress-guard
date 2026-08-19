package main

import (
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/byliu-labs/egress-guard/internal/decisionlog"
)

func TestQuantileAndBaseOf(t *testing.T) {
	if got := quantile([]float64{1, 2, 3, 4, 5}, 0.9); got != 4 {
		t.Fatalf("quantile = %v", got)
	}
	if got := baseOf("/usr/bin/git"); got != "git" {
		t.Fatalf("baseOf = %q", got)
	}
}

func TestScoresForEntriesPreservesPathSensitiveIdentity(t *testing.T) {
	entries := []decisionlog.Entry{
		{Kind: decisionlog.KindDecision, ConnID: "a", Timestamp: "2026-08-17T14:00:00Z", Decision: decisionlog.DecisionAllow, Exe: "/usr/bin/git", ExeSHA256: "abc123", Host: "github.com"},
		{Kind: decisionlog.KindFlow, ConnID: "a", BytesUp: 1, BytesDown: 1, DurationMS: 1},
		{Kind: decisionlog.KindDecision, ConnID: "b", Timestamp: "2026-08-18T14:00:00Z", Decision: decisionlog.DecisionAllow, Exe: "/usr/bin/git", ExeSHA256: "abc123", Host: "github.com"},
		{Kind: decisionlog.KindFlow, ConnID: "b", BytesUp: 2, BytesDown: 1, DurationMS: 1},
		{Kind: decisionlog.KindDecision, ConnID: "c", Timestamp: "2026-08-19T14:00:00Z", Decision: decisionlog.DecisionAllow, Exe: "/usr/bin/git", ExeSHA256: "abc123", Host: "github.com"},
		{Kind: decisionlog.KindFlow, ConnID: "c", BytesUp: 3, BytesDown: 1, DurationMS: 1},
	}
	scores, infinite, unscorable := scoresForEntries(entries, 0.7)
	if len(scores) != 1 || infinite != 0 || unscorable != 0 {
		t.Fatalf("scores=%v infinite=%d unscorable=%d", scores, infinite, unscorable)
	}
}

// A real log always contains decisions with no flow record: the connection is
// still open, the daemon restarted, or rotation aged the flow out. Those are
// non-measurements. Folding them into the sample as distance 0 reports a
// median joint distance of zero and understates the prompt rate of every
// threshold read off these quantiles — which is the whole output of the tool.
func TestScoresForEntriesExcludesUnscorableDecisions(t *testing.T) {
	var entries []decisionlog.Entry
	add := func(id, ts string, withFlow bool) {
		entries = append(entries, decisionlog.Entry{
			Kind: decisionlog.KindDecision, ConnID: id, Timestamp: ts,
			Decision: decisionlog.DecisionAllow, Exe: "/usr/bin/git",
			ExeSHA256: "abc123", Host: "github.com"})
		if withFlow {
			entries = append(entries, decisionlog.Entry{Kind: decisionlog.KindFlow,
				ConnID: id, BytesUp: 20000, BytesDown: 30000, DurationMS: 500})
		}
	}
	for i := 0; i < 20; i++ {
		add(fmt.Sprintf("t%02d", i), fmt.Sprintf("2026-08-%02dT14:00:00Z", 1+i%20), true)
	}
	for i := 0; i < 5; i++ {
		add(fmt.Sprintf("e%02d", i), "2026-08-21T14:00:00Z", true)
	}
	for i := 0; i < 5; i++ {
		add(fmt.Sprintf("n%02d", i), "2026-08-21T15:00:00Z", false)
	}

	scores, infinite, unscorable := scoresForEntries(entries, 0.666)
	if unscorable != 5 {
		t.Fatalf("unscorable = %d, want the 5 flowless decisions", unscorable)
	}
	// Note the sample legitimately contains a measured 0: a connection
	// identical to its own history really is at distance 0. That is exactly
	// why the flowless ones cannot be folded in as 0 too — the two are
	// indistinguishable once mixed, and only one of them is a measurement.
	if len(scores)+infinite != 6 {
		t.Fatalf("sample = %d scored + %d infinite, want the 6 scorable connections and nothing else",
			len(scores), infinite)
	}
}

// Calibration must score connections in the same space the clouds were built
// in. BuildBaseline derives each historical point's concurrency from the log,
// so scoring a held-out connection as if nothing else was egressing puts a
// constant offset on that axis for every connection that had company — the
// quantiles then describe a distribution the daemon will never produce, and
// the threshold read off them is calibrated against the wrong geometry.
func TestScoresForEntries_ScoresConcurrencyInTheCloudsOwnSpace(t *testing.T) {
	base := time.Date(2026, 1, 1, 9, 0, 0, 0, time.UTC)
	var entries []decisionlog.Entry
	id := 0
	for slot := 0; slot < 40; slot++ {
		stamp := base.Add(time.Duration(slot) * 30 * time.Second).Format(time.RFC3339)
		for k := 0; k < 12; k++ { // every connection arrives in a burst of 12
			conn := fmt.Sprintf("c%d", id)
			entries = append(entries,
				decisionlog.Entry{Kind: decisionlog.KindDecision, ConnID: conn, Timestamp: stamp,
					Decision: decisionlog.DecisionAllow, Exe: "/usr/bin/git", Comm: "git", Host: "github.com"},
				decisionlog.Entry{Kind: decisionlog.KindFlow, ConnID: conn, Timestamp: stamp,
					BytesUp: 1000, BytesDown: 2000, DurationMS: 8000})
			id++
		}
	}

	scores, infinite, unscorable := scoresForEntries(entries, 0.7)
	if len(scores) == 0 || infinite != 0 || unscorable != 0 {
		t.Fatalf("sample = %d scored, %d infinite, %d unscorable", len(scores), infinite, unscorable)
	}
	sort.Float64s(scores)

	// Every connection here is identical to its history in every dimension,
	// concurrency included, so the closest of them must sit at zero. Scoring
	// with a hardcoded concurrency of 0 offsets EVERY connection from clouds
	// that carry log1p(11), so even the closest lands tens of units out.
	//
	// The assertion is on the minimum rather than the median because a second,
	// pre-existing defect inflates the rest: LastSeenFor freezes at the last
	// training timestamp, so "time since the last connection" grows without
	// bound across the held-out set and dominates every later score. That is
	// not this property and is not fixed here.
	if closest := scores[0]; closest > 0.5 {
		t.Fatalf("closest distance = %.3f for a log where every connection matches its own history; "+
			"the scoring side is not deriving concurrency the way BuildBaseline does", closest)
	}
}
