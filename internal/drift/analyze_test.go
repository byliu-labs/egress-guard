package drift

import (
	"testing"
	"time"

	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/decisionlog"
)

func TestAnalyzeReturnsOnlyDriftRankedHighestFirst(t *testing.T) {
	baseTime := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)
	learned := []decisionlog.Entry{
		{Timestamp: baseTime.Format(time.RFC3339), Decision: decisionlog.DecisionAllow, Exe: "/Applications/Slack.app/MacOS/Slack", TeamID: "TEAMSLACK", Host: "slack.com"},
		{Timestamp: baseTime.AddDate(0, 0, 1).Format(time.RFC3339), Decision: decisionlog.DecisionAllow, Exe: "/Applications/Slack.app/MacOS/Slack", TeamID: "TEAMSLACK", Host: "slack.com"},
	}
	b := BuildBaseline(nil, learned)

	window := []decisionlog.Entry{
		{Timestamp: baseTime.AddDate(0, 0, 2).Format(time.RFC3339), Decision: decisionlog.DecisionAllow, Exe: "/Applications/Slack.app/MacOS/Slack", TeamID: "TEAMSLACK", Host: "slack.com"},
		{Timestamp: baseTime.AddDate(0, 0, 2).Format(time.RFC3339), Decision: decisionlog.DecisionAllow, Exe: "/Applications/Slack.app/MacOS/Slack", TeamID: "TEAMSLACK", Host: "unseen-host.example.com"},
		{Timestamp: baseTime.AddDate(0, 0, 2).Format(time.RFC3339), Decision: decisionlog.DecisionAllow, Exe: "/tmp/mystery-binary", Host: "slack.com"},
	}
	events := Analyze(window, b)

	if len(events) != 2 {
		t.Fatalf("Analyze returned %d events, want 2 (known entries must be excluded)", len(events))
	}
	if events[0].Reason != ReasonNovelIdentity {
		t.Errorf("events[0].Reason = %q, want %q (highest rank first)", events[0].Reason, ReasonNovelIdentity)
	}
	if events[1].Reason != ReasonNovelDestination {
		t.Errorf("events[1].Reason = %q, want %q", events[1].Reason, ReasonNovelDestination)
	}
	for _, ev := range events {
		if ev.Class != ClassDrift {
			t.Errorf("Analyze must return drift-only events, got Class=%q", ev.Class)
		}
	}
}

func TestReplayDecisionLog_SteadyStateSilentNoveltiesSurface(t *testing.T) {
	cat, err := catalog.Load([]byte(""))
	if err != nil {
		t.Fatalf("catalog.Load(empty): %v", err)
	}
	if err := cat.Add(catalog.Entry{
		SchemaVersion:        catalog.CurrentSchemaVersion,
		Identity:             catalog.Identity{ExeBasename: "Chrome", TeamID: "TEAMCHROME"},
		ExpectedDestinations: []catalog.Destination{{Host: "google.com", Why: "sync"}},
		Explanation:          "Chrome talks to Google services",
		Evidence:             "vendor docs",
		Confidence:           catalog.ConfidenceHigh,
		Layer:                "baseline",
	}); err != nil {
		t.Fatalf("cat.Add: %v", err)
	}

	steadyIdentities := []struct {
		exe    string
		teamID string
		host   string
	}{
		{"/Applications/Slack.app/MacOS/Slack", "TEAMSLACK", "slack.com"},
		{"/Applications/Google Chrome.app/MacOS/Chrome", "TEAMCHROME", "google.com"},
		{"/usr/libexec/backupd", "TEAMAPPLE", "backup.example.com"},
	}
	baseDay := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)
	var history []decisionlog.Entry
	for day := 0; day < 6; day++ {
		for _, id := range steadyIdentities {
			history = append(history, decisionlog.Entry{
				Timestamp: baseDay.AddDate(0, 0, day).Format(time.RFC3339),
				Decision:  decisionlog.DecisionAllow,
				Exe:       id.exe,
				TeamID:    id.teamID,
				Host:      id.host,
			})
		}
	}
	baseline := BuildBaseline(cat, history)

	window := make([]decisionlog.Entry, 0, len(steadyIdentities)+3)
	for _, id := range steadyIdentities {
		window = append(window, decisionlog.Entry{
			Timestamp: baseDay.AddDate(0, 0, 6).Format(time.RFC3339),
			Decision:  decisionlog.DecisionAllow,
			Exe:       id.exe,
			TeamID:    id.teamID,
			Host:      id.host,
		})
	}
	window = append(window,
		decisionlog.Entry{Timestamp: baseDay.AddDate(0, 0, 6).Format(time.RFC3339), Decision: decisionlog.DecisionAllow, Exe: "/tmp/new-agent-binary", Host: "slack.com"},
		decisionlog.Entry{Timestamp: baseDay.AddDate(0, 0, 6).Format(time.RFC3339), Decision: decisionlog.DecisionAllow, Exe: "/Applications/Slack.app/MacOS/Slack", TeamID: "TEAMSLACK", Host: "exfil.example.net"},
		decisionlog.Entry{Timestamp: baseDay.AddDate(0, 0, 6).Format(time.RFC3339), Decision: decisionlog.DecisionAllow, Exe: "/Applications/Slack.app/MacOS/Slack", TeamID: "TEAMSLACK", Host: "google.com"},
	)

	events := Analyze(window, baseline)
	if len(events) != 3 {
		t.Fatalf("Analyze found %d drift events, want exactly the 3 injected novelties", len(events))
	}
	gotReasons := map[DriftReason]bool{}
	for _, ev := range events {
		gotReasons[ev.Reason] = true
	}
	for _, want := range []DriftReason{ReasonNovelIdentity, ReasonNovelDestination, ReasonNovelPairing} {
		if !gotReasons[want] {
			t.Errorf("expected a drift event with reason %q, got reasons %v", want, gotReasons)
		}
	}
	if events[0].Reason != ReasonNovelIdentity {
		t.Errorf("events[0].Reason = %q, want %q", events[0].Reason, ReasonNovelIdentity)
	}
}

func TestFatigueProperty_WeekOneLogYieldsDriftOnASmallMinority(t *testing.T) {
	cat, err := catalog.Load([]byte(""))
	if err != nil {
		t.Fatalf("catalog.Load(empty): %v", err)
	}
	steady := []struct {
		exe    string
		teamID string
		hosts  []string
	}{
		{"/Applications/Slack.app/MacOS/Slack", "TEAMSLACK", []string{"slack.com", "slack-edge.com"}},
		{"/Applications/Google Chrome.app/MacOS/Chrome", "TEAMCHROME", []string{"google.com"}},
		{"/usr/libexec/backupd", "TEAMAPPLE", []string{"backup.example.com"}},
		{"/usr/libexec/rapportd", "TEAMAPPLE", []string{"gateway.icloud.com"}},
		{"/Applications/Spotify.app/MacOS/Spotify", "TEAMSPOTIFY", []string{"spotify.com"}},
	}

	baseDay := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)
	var all []decisionlog.Entry
	for day := 0; day < 7; day++ {
		for _, s := range steady {
			for _, host := range s.hosts {
				for i := 0; i < 4; i++ {
					all = append(all, decisionlog.Entry{
						Timestamp: baseDay.AddDate(0, 0, day).Add(time.Duration(i) * time.Hour).Format(time.RFC3339),
						Decision:  decisionlog.DecisionAllow,
						Exe:       s.exe,
						TeamID:    s.teamID,
						Host:      host,
					})
				}
			}
		}
	}
	steadyTotal := len(all)
	novelties := []decisionlog.Entry{
		{Timestamp: baseDay.AddDate(0, 0, 6).Format(time.RFC3339), Decision: decisionlog.DecisionAllow, Exe: "/tmp/curl-dropped-by-installer", Host: "raw-download.example.net"},
		{Timestamp: baseDay.AddDate(0, 0, 6).Format(time.RFC3339), Decision: decisionlog.DecisionAllow, Exe: "/Applications/Spotify.app/MacOS/Spotify", TeamID: "TEAMSPOTIFY", Host: "telemetry-unknown.example.net"},
	}

	var history, window []decisionlog.Entry
	for _, e := range all {
		ts, _ := time.Parse(time.RFC3339, e.Timestamp)
		if ts.Before(baseDay.AddDate(0, 0, 6)) {
			history = append(history, e)
		} else {
			window = append(window, e)
		}
	}
	window = append(window, novelties...)
	baseline := BuildBaseline(cat, history)
	events := Analyze(window, baseline)

	windowTotal := len(window)
	driftTotal := len(events)
	if driftTotal == 0 {
		t.Fatalf("expected injected novelties to surface as drift, got 0 drift events out of %d connections", windowTotal)
	}
	if ratio := float64(driftTotal) / float64(windowTotal); ratio > 0.25 {
		t.Errorf("fatigue property violated: drift ratio = %.2f (%d/%d), want <= 0.25", ratio, driftTotal, windowTotal)
	}
	t.Logf("history=%d window=%d drift=%d ratio=%.3f", steadyTotal, windowTotal, driftTotal, float64(driftTotal)/float64(windowTotal))
}
