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
	if !math.IsInf(novel.Score.Distance, 1) {
		t.Fatalf("novel score = %v", novel.Score.Distance)
	}
	known := baseline.Classify(decisionlog.Entry{Timestamp: "2026-08-19T14:00:00Z", Exe: "/usr/bin/git", Host: "github.com"})
	if math.IsInf(known.Score.Distance, 1) {
		t.Fatalf("known score = %v", known.Score.Distance)
	}
}

func TestScoreLiveAttributesAndExplainIsHonest(t *testing.T) {
	entries := append(flowPair("a1", "2026-08-17T14:00:00Z", "/usr/bin/git", "github.com", 1, decisionlog.DecisionAllow), flowPair("a2", "2026-08-18T14:00:00Z", "/usr/bin/git", "github.com", 1, decisionlog.DecisionAllow)...)
	baseline := BuildBaseline(&catalog.Catalog{}, entries)
	score := baseline.ScoreLive(catalog.Identity{ExeBasename: "git"}, "github.com", testJoined("2026-08-19T03:00:00Z", 4_000_000, 1, 9000, nil))
	if score.Distance < 1 || len(score.Dominant) == 0 {
		t.Fatalf("score = %+v", score)
	}
	explanation := (Event{Score: score}).Explain()
	if !strings.Contains(explanation, DimNames[score.Dominant[0]]) {
		t.Fatalf("explanation = %q", explanation)
	}
	if strings.Contains((Event{Score: Score{Distance: math.Inf(1)}}).Explain(), "nearest") {
		t.Fatal("empty-history explanation invented a neighbour")
	}
}
