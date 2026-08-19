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

func TestDaemonAndReplayScoreTheSameConnectionIdentically(t *testing.T) {
	_, hash, err := procid.NewExeHasher().Hash("/usr/bin/curl")
	if err != nil {
		t.Fatal(err)
	}
	history := steadyPairHistory(hash, time.Minute, 40)
	train, held := history[:len(history)-2], history[len(history)-2:]
	baseline := drift.BuildBaseline(&catalog.Catalog{}, train)

	replay := newLastSeen(64)
	replay.seed(baseline)
	joined := decisionlog.Join(held)[0]
	want := baseline.ScoreAgainst(
		drift.IdentityFromEntry(joined.Decision), joined.Decision.Host, joined,
		replay.at(drift.BaselinePairKey(joined.Decision)), 0,
	)

	var got drift.Event
	runAllowedConnectionWithDaemon(t, 512, func(d *Daemon) {
		d.SetBaseline(baseline)
		d.now = func() time.Time { return steadyPairEnd }
		d.onCompletedScore = func(ev drift.Event) { got = ev }
	})

	if !got.Score.Scored {
		t.Fatalf("daemon score = %+v, want a scored point", got.Score)
	}
	if math.Abs(got.Score.Distance-want.Distance) > 1e-9 {
		t.Fatalf("daemon = %v, replay = %v; the two spaces have diverged", got.Score.Distance, want.Distance)
	}
}
