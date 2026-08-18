package main

import (
	"testing"

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
	scores, infinite := scoresForEntries(entries, 0.7)
	if len(scores) != 1 || infinite != 0 {
		t.Fatalf("scores=%v infinite=%d", scores, infinite)
	}
}
