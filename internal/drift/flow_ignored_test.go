package drift

import (
	"testing"

	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/decisionlog"
)

// A flow record must not be able to establish a pair as "known" on its own.
// Only the decision that authorized the connection may do that.
func TestBuildBaseline_IgnoresFlowRecords(t *testing.T) {
	cat, err := catalog.Load([]byte{})
	if err != nil {
		t.Fatal(err)
	}
	dec := func(ts string) decisionlog.Entry {
		return decisionlog.Entry{Timestamp: ts, Decision: decisionlog.DecisionAllow,
			Exe: "/usr/bin/curl", Host: "pypi.org"}
	}
	flow := func(ts string) decisionlog.Entry {
		e := dec(ts)
		e.Kind = decisionlog.KindFlow
		e.ConnID = "0123456789abcdef"
		return e
	}
	// One real day of decisions, one day of flow records only.
	b := BuildBaseline(cat, []decisionlog.Entry{dec("2026-08-13T10:00:00Z"), flow("2026-08-14T10:00:00Z")})

	ev := b.Classify(dec("2026-08-15T10:00:00Z"))
	if ev.Class == ClassKnown {
		t.Fatal("a flow record counted as a second stable day; a pair became known without a second decision")
	}
}
