package drift

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/byliu-labs/egress-guard/internal/decisionlog"
)

func TestE2EReplayDecisionLogFileBuildsBaselineAndSurfacesDrift(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decision.log")
	writer, err := decisionlog.Open(path)
	if err != nil {
		t.Fatalf("decisionlog.Open: %v", err)
	}
	base := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)
	for _, e := range []decisionlog.Entry{
		{Timestamp: base.Format(time.RFC3339), Decision: decisionlog.DecisionAllow, Exe: "/Applications/Slack.app/MacOS/Slack", TeamID: "TEAMSLACK", Host: "slack.com"},
		{Timestamp: base.AddDate(0, 0, 1).Format(time.RFC3339), Decision: decisionlog.DecisionAllow, Exe: "/Applications/Slack.app/MacOS/Slack", TeamID: "TEAMSLACK", Host: "slack.com"},
		{Timestamp: base.AddDate(0, 0, 2).Format(time.RFC3339), Decision: decisionlog.DecisionAllow, Exe: "/Applications/Slack.app/MacOS/Slack", TeamID: "TEAMSLACK", Host: "slack.com"},
		{Timestamp: base.AddDate(0, 0, 2).Format(time.RFC3339), Decision: decisionlog.DecisionAllow, Exe: "/tmp/installer-curl", Host: "exfil.example.net"},
	} {
		if err := writer.Write(e); err != nil {
			t.Fatalf("decisionlog.Write: %v", err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("decisionlog.Close: %v", err)
	}

	entries, err := decisionlog.Read(path)
	if err != nil {
		t.Fatalf("decisionlog.Read: %v", err)
	}
	baseline := BuildBaseline(nil, entries[:2])
	events := Analyze(entries[2:], baseline)
	if len(events) != 1 {
		t.Fatalf("Analyze(file replay) returned %d drift events, want 1", len(events))
	}
	if events[0].Reason != ReasonNovelIdentity || events[0].Host != "exfil.example.net" {
		t.Errorf("unexpected drift event: %+v", events[0])
	}
}
