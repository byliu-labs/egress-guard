package main

import (
	"github.com/byliu-labs/egress-guard/internal/decisionlog"
	"testing"
)

type rejectExample struct{}

func (rejectExample) Contains(_, _, _, host string) bool { return host == "evil.example" }
func (rejectExample) Digest() string                     { return "rejected" }

func TestCalibrationExcludesRejectedTrainingPair(t *testing.T) {
	entries := []decisionlog.Entry{
		{Kind: decisionlog.KindDecision, ConnID: "a", Timestamp: "2026-08-01T00:00:00Z", Decision: decisionlog.DecisionAllow, Exe: "/bin/curl", Host: "evil.example"},
		{Kind: decisionlog.KindFlow, ConnID: "a", BytesUp: 1, BytesDown: 1, DurationMS: 1},
		{Kind: decisionlog.KindDecision, ConnID: "b", Timestamp: "2026-08-02T00:00:00Z", Decision: decisionlog.DecisionAllow, Exe: "/bin/curl", Host: "evil.example"},
		{Kind: decisionlog.KindFlow, ConnID: "b", BytesUp: 1, BytesDown: 1, DurationMS: 1},
		{Kind: decisionlog.KindDecision, ConnID: "c", Timestamp: "2026-08-03T00:00:00Z", Decision: decisionlog.DecisionAllow, Exe: "/bin/curl", Host: "evil.example"},
		{Kind: decisionlog.KindFlow, ConnID: "c", BytesUp: 1, BytesDown: 1, DurationMS: 1},
	}
	_, infinite, _ := scoresForEntries(entries, 0.67, rejectExample{})
	if infinite != 1 {
		t.Fatalf("infinite=%d, want rejected held-out pair with no training cloud", infinite)
	}
}
