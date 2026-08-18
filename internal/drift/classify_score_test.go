package drift

import (
	"math"
	"strings"
	"testing"

	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/decisionlog"
)

func TestClassifyScoresNovelPairAsInfiniteAndKnownPairAsFinite(t *testing.T) {
	entries := append(flowPair("a1", "2026-08-17T14:00:00Z", "/usr/bin/git", "github.com", 1000, decisionlog.DecisionAllow), flowPair("a2", "2026-08-18T14:00:00Z", "/usr/bin/git", "github.com", 1000, decisionlog.DecisionAllow)...)
	baseline := BuildBaseline(&catalog.Catalog{}, entries)
	novel := baseline.Classify(decisionlog.Entry{Timestamp: "2026-08-19T14:00:00Z", Exe: "/usr/bin/curl", Host: "new.example"})
	if novel.Score.Scored {
		t.Fatalf("live novel score must be explicitly unscored: %+v", novel.Score)
	}
	known := baseline.Classify(decisionlog.Entry{Timestamp: "2026-08-19T14:00:00Z", Exe: "/usr/bin/git", Host: "github.com"})
	if known.Score.Scored || known.Score.Distance != 0 {
		t.Fatalf("live known score must be explicitly unscored: %+v", known.Score)
	}
}

func TestScoreLiveAttributesAndExplainIsHonest(t *testing.T) {
	entries := append(flowPair("a1", "2026-08-17T14:00:00Z", "/usr/bin/git", "github.com", 1, decisionlog.DecisionAllow), flowPair("a2", "2026-08-18T14:00:00Z", "/usr/bin/git", "github.com", 1, decisionlog.DecisionAllow)...)
	baseline := BuildBaseline(&catalog.Catalog{}, entries)
	score := baseline.ScoreLive(catalog.Identity{ExeBasename: "git"}, "github.com", testJoined("2026-08-19T03:00:00Z", 4_000_000, 1, 9000, nil), 0)
	if !score.Scored || score.Distance < 1 || len(score.Dominant) == 0 {
		t.Fatalf("score = %+v", score)
	}
	explanation := (Event{Score: score}).Explain()
	if !strings.Contains(explanation, DimNames[score.Dominant[0]]) {
		t.Fatalf("explanation = %q", explanation)
	}
	if strings.Contains((Event{Score: Score{Scored: true, Distance: math.Inf(1)}}).Explain(), "nearest") {
		t.Fatal("empty-history explanation invented a neighbour")
	}
	if got := (Event{Score: Score{}}).Explain(); !strings.Contains(got, "not available") {
		t.Fatalf("unscored explanation = %q", got)
	}
}

func TestScoreLiveAddsInFlightConcurrencyToTheScore(t *testing.T) {
	entries := append(flowPair("a1", "2026-08-17T14:00:00Z", "/usr/bin/git", "github.com", 1, decisionlog.DecisionAllow), flowPair("a2", "2026-08-18T14:00:00Z", "/usr/bin/git", "github.com", 1, decisionlog.DecisionAllow)...)
	baseline := BuildBaseline(&catalog.Catalog{}, entries)
	score := baseline.ScoreLive(catalog.Identity{ExeBasename: "git"}, "github.com", testJoined("2026-08-19T14:00:00Z", 1, 100, 50, nil), 9)
	if !score.Scored || score.Distance == 0 {
		t.Fatalf("live concurrency was not scored: %+v", score)
	}
}
