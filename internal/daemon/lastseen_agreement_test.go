package daemon

import (
	"math"
	"testing"
	"time"

	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/decisionlog"
	"github.com/byliu-labs/egress-guard/internal/drift"
	"github.com/byliu-labs/egress-guard/internal/procid"
)

func TestDaemonAndReplayScoreHeldOutConnectionsIdentically(t *testing.T) {
	_, hash, err := procid.NewExeHasher().Hash("/usr/bin/curl")
	if err != nil {
		t.Fatal(err)
	}
	history := steadyPairHistory(hash, time.Minute, 40)
	train, held := history[:len(history)-4], history[len(history)-4:]
	baseline := drift.BuildBaseline(&catalog.Catalog{}, train)

	d := newDaemonForBaselineTest()
	d.SetBaseline(baseline)
	d.now = func() time.Time { return baseline.BuiltThrough().Add(time.Hour) }
	joined := decisionlog.Join(held)
	replayLastSeen := make(map[string]time.Time, len(baseline.Pairs()))
	for _, pair := range baseline.Pairs() {
		replayLastSeen[drift.BaselinePairKeyFor(pair.Identity, pair.Host)] = baseline.LastSeenFor(pair.Identity, pair.Host)
	}

	for _, item := range joined {
		key := drift.BaselinePairKey(item.Decision)
		want := baseline.ScoreAgainst(
			drift.IdentityFromEntry(item.Decision), item.Decision.Host, item,
			replayLastSeen[key], 0,
		)
		got := d.classifyCompletedFlow(item.Decision, item.Flow, 0)
		if !got.Score.Scored {
			t.Fatalf("daemon score = %+v, want a scored point", got.Score)
		}
		if math.Abs(got.Score.Distance-want.Distance) > 1e-9 {
			t.Fatalf("daemon = %v, replay = %v; the two spaces have diverged", got.Score.Distance, want.Distance)
		}

		at, err := time.Parse(time.RFC3339, item.Decision.Timestamp)
		if err != nil {
			t.Fatal(err)
		}
		if drift.FoldsIntoBaseline(item.Decision) {
			d.lastSeen.advanceEntry(item.Decision)
			replayLastSeen[key] = at
		}
	}
}
