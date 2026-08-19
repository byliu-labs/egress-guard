package drift

import (
	"fmt"
	"testing"

	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/decisionlog"
)

// TestConcurrency_IsDerivedFromHistoryThatPredatesIt protects the reason this
// dimension is derived: records written before the feature existed still carry
// enough information for their concurrency to be reconstructed.
func TestConcurrency_IsDerivedFromHistoryThatPredatesIt(t *testing.T) {
	overlapping := historyFor(t, []string{
		"2026-01-01T09:00:00Z", "2026-01-01T09:00:01Z",
		"2026-01-01T09:00:02Z", "2026-01-01T09:00:03Z",
	}, 60_000)
	spaced := historyFor(t, []string{
		"2026-01-01T09:00:00Z", "2026-01-01T10:00:00Z",
		"2026-01-01T11:00:00Z", "2026-01-01T12:00:00Z",
	}, 1_000)

	over := cloudOfPair(t, overlapping)
	apart := cloudOfPair(t, spaced)
	if len(over) != 4 || len(apart) != 4 {
		t.Fatalf("clouds have %d and %d points, want 4 each", len(over), len(apart))
	}

	var overSum, apartSum float64
	for i := range over {
		overSum += over[i][DimConcurrency]
		apartSum += apart[i][DimConcurrency]
	}
	if apartSum != 0 {
		t.Errorf("non-overlapping history produced concurrency %v, want 0", apartSum)
	}
	if overSum <= 0 {
		t.Fatalf("overlapping history produced concurrency %v; the dimension is not being derived from history", overSum)
	}
}

func historyFor(t *testing.T, stamps []string, durationMS int64) []decisionlog.Entry {
	t.Helper()
	var entries []decisionlog.Entry
	for i, timestamp := range stamps {
		pair := flowPair(fmt.Sprintf("old%d", i), timestamp, "/usr/bin/git", "github.com", 1000, decisionlog.DecisionAllow)
		pair[1].DurationMS = durationMS
		entries = append(entries, pair...)
	}
	return entries
}

func cloudOfPair(t *testing.T, entries []decisionlog.Entry) []Point {
	t.Helper()
	baseline := BuildBaseline(&catalog.Catalog{}, entries)
	cloud, _ := baseline.CloudFor(catalog.Identity{ExeBasename: "git"}, "github.com")
	return cloud
}
