package drift

import (
	"testing"
	"time"

	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/decisionlog"
)

func learnedEntry(ts, exe, host string) decisionlog.Entry {
	return decisionlog.Entry{Timestamp: ts, Exe: exe, Host: host, Decision: decisionlog.DecisionAllow}
}

func TestLearnedRecordsStablePairsAndProvenance(t *testing.T) {
	b := BuildBaseline(&catalog.Catalog{}, []decisionlog.Entry{
		learnedEntry("2026-08-03T09:00:00Z", "/usr/bin/git", "github.com"),
		learnedEntry("2026-08-01T09:00:00Z", "/usr/bin/git", "github.com"),
		learnedEntry("2026-08-05T09:00:00Z", "/usr/bin/git", "github.com"),
		learnedEntry("2026-08-05T09:00:00Z", "/usr/bin/curl", "one-day.example"),
	})
	got := b.Learned()
	if len(got) != 2 || got[1].Host != "github.com" || got[1].Count != 3 || got[1].FirstSeen.Format("2006-01-02") != "2026-08-01" || got[1].LastSeen.Format("2006-01-02") != "2026-08-05" {
		t.Fatalf("Learned = %+v", got)
	}
	if recent := b.LearnedSince(time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC)); len(recent) != 1 || recent[0].Host != "one-day.example" {
		t.Fatalf("recent review = %+v", recent)
	}
}

func TestLearnedSurvivesSnapshot(t *testing.T) {
	b := BuildBaseline(nil, []decisionlog.Entry{learnedEntry("2026-08-01T00:00:00Z", "/bin/git", "github.com"), learnedEntry("2026-08-02T00:00:00Z", "/bin/git", "github.com")})
	path := t.TempDir() + "/baseline.json"
	if err := b.Save(path); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadBaseline(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := loaded.Learned(); len(got) != 1 || got[0].Count != 2 {
		t.Fatalf("loaded Learned = %+v", got)
	}
}

func TestLearnedIncludesOneDayCloudPair(t *testing.T) {
	b := BuildBaseline(nil, []decisionlog.Entry{learnedEntry("2026-08-01T00:00:00Z", "/bin/curl", "new.example")})
	if len(b.Pairs()) != 1 {
		t.Fatal("fixture did not enter scoring cloud")
	}
	if got := b.Learned(); len(got) != 1 || got[0].Host != "new.example" {
		t.Fatalf("review hides one-day cloud: %+v", got)
	}
}
