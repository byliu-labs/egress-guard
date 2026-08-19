package drift

import (
	"math"
	"strings"
	"testing"
	"time"

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
	joined := testJoined("2026-08-19T14:00:00Z", 1, 100, 50, nil)
	pair := catalog.Identity{ExeBasename: "git"}
	busy := baseline.ScoreLive(pair, "github.com", joined, 9)
	quiet := baseline.ScoreLive(pair, "github.com", joined, 0)
	if !busy.Scored || !quiet.Scored {
		t.Fatalf("scores = %+v / %+v, want both scored", busy, quiet)
	}
	// Compared against the same connection scored as if nothing else was
	// egressing. Asserting only that the distance is non-zero would pass with
	// the dimension hard-wired to zero, since the other eight already differ.
	if busy.Distance <= quiet.Distance {
		t.Fatalf("concurrency did not reach the score: busy=%v quiet=%v", busy.Distance, quiet.Distance)
	}
}

// ScoreLive must be exactly ScoreAgainst with the baseline's own last-seen.
// If they ever diverge, the daemon and the calibrator are scoring in two
// different spaces and the thresholds read off one do not apply to the other.
func TestScoreLiveDelegatesToScoreAgainstWithStoredLastSeen(t *testing.T) {
	entries := append(
		flowPair("a1", "2026-08-17T14:00:00Z", "/usr/bin/git", "github.com", 1, decisionlog.DecisionAllow),
		flowPair("a2", "2026-08-18T14:00:00Z", "/usr/bin/git", "github.com", 1, decisionlog.DecisionAllow)...)
	baseline := BuildBaseline(&catalog.Catalog{}, entries)
	pair := catalog.Identity{ExeBasename: "git"}
	joined := testJoined("2026-08-19T03:00:00Z", 4_000_000, 1, 9000, nil)

	live := baseline.ScoreLive(pair, "github.com", joined, 3)
	same := baseline.ScoreAgainst(pair, "github.com", joined, baseline.LastSeenFor(pair, "github.com"), 3)
	if live.Distance != same.Distance || live.Scored != same.Scored {
		t.Fatalf("ScoreLive = %+v, ScoreAgainst(storedLastSeen) = %+v; they must agree", live, same)
	}
}

// The supplied prev must actually reach DimInterArrival. A replaying caller
// advances it per connection; if ScoreAgainst ignored it in favour of the
// baseline's frozen value, calibration would measure file position again.
func TestScoreAgainstHonoursSuppliedPrev(t *testing.T) {
	entries := append(
		flowPair("a1", "2026-08-17T14:00:00Z", "/usr/bin/git", "github.com", 1, decisionlog.DecisionAllow),
		flowPair("a2", "2026-08-18T14:00:00Z", "/usr/bin/git", "github.com", 1, decisionlog.DecisionAllow)...)
	baseline := BuildBaseline(&catalog.Catalog{}, entries)
	pair := catalog.Identity{ExeBasename: "git"}
	joined := testJoined("2026-08-19T03:00:00Z", 1, 100, 50, nil)

	stale, _ := time.Parse(time.RFC3339, "2026-08-18T14:00:00Z")
	recent, _ := time.Parse(time.RFC3339, "2026-08-19T02:59:00Z")
	far := baseline.ScoreAgainst(pair, "github.com", joined, stale, 0)
	near := baseline.ScoreAgainst(pair, "github.com", joined, recent, 0)
	if far.Distance == near.Distance {
		t.Fatalf("prev was ignored: stale and recent both scored %v", far.Distance)
	}
}
