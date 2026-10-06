package daemon

import (
	"github.com/byliu-labs/egress-guard/internal/decisionlog"
	"github.com/byliu-labs/egress-guard/internal/drift"
	"testing"
)

type rejectForSeed struct{}

func (rejectForSeed) Contains(_, _, _, host string) bool { return host == "evil.example" }
func (rejectForSeed) Digest() string                     { return "evil.example" }

func TestLiveReferenceExcludesRejectedPair(t *testing.T) {
	entry := decisionlog.Entry{Timestamp: "2026-08-01T00:00:00Z", Exe: "/bin/curl", Host: "evil.example", Decision: decisionlog.DecisionAllow}
	baseline := drift.BuildBaselineWithRejections(nil, []decisionlog.Entry{entry}, rejectForSeed{})
	refs := newLastSeen(8)
	refs.seed(baseline)
	if at := refs.at(drift.BaselinePairKey(entry)); !at.IsZero() {
		t.Fatalf("rejected pair seeded live reference at %v", at)
	}
}
