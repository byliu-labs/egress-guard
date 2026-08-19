package decisionlog

import (
	"strconv"
	"testing"
	"time"
)

func at(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func conn(id, ts string, durationMS int64) Joined {
	return Joined{
		Decision: Entry{Kind: KindDecision, ConnID: id, Timestamp: ts, Host: "a.example"},
		Flow:     Entry{Kind: KindFlow, ConnID: id, DurationMS: durationMS},
		HasFlow:  true,
	}
}

func TestConcurrencyIndex_CountsOverlappingConnections(t *testing.T) {
	idx := BuildConcurrencyIndex([]Joined{
		conn("a", "2026-08-17T14:00:00Z", 10_000), // 14:00:00 - 14:00:10
		conn("b", "2026-08-17T14:00:02Z", 10_000), // 14:00:02 - 14:00:12
		conn("c", "2026-08-17T14:00:04Z", 1_000),  // 14:00:04 - 14:00:05
	})
	if got := idx.At(at("2026-08-17T14:00:04Z"), ""); got != 3 {
		t.Errorf("At(14:00:04) = %d, want 3", got)
	}
	if got := idx.At(at("2026-08-17T14:00:11Z"), ""); got != 1 {
		t.Errorf("At(14:00:11) = %d, want 1 (only b still open)", got)
	}
	if got := idx.At(at("2026-08-17T14:00:20Z"), ""); got != 0 {
		t.Errorf("At(14:00:20) = %d, want 0", got)
	}
}

// "What ELSE was egressing." A connection that always sees at least itself has
// a constant offset carrying no information.
func TestConcurrencyIndex_ExcludesTheSubjectConnection(t *testing.T) {
	idx := BuildConcurrencyIndex([]Joined{
		conn("a", "2026-08-17T14:00:00Z", 10_000),
	})
	if got := idx.At(at("2026-08-17T14:00:05Z"), "a"); got != 0 {
		t.Errorf("At = %d, want 0: a connection must not count itself", got)
	}
	if got := idx.At(at("2026-08-17T14:00:05Z"), ""); got != 1 {
		t.Errorf("At = %d, want 1 with no exclusion", got)
	}
}

// A denied connection never splices and has no flow record, so no duration.
// It is still an egress attempt at that instant and must be counted.
func TestConcurrencyIndex_CountsDeniedConnectionsAsInstants(t *testing.T) {
	denied := Joined{Decision: Entry{Kind: KindDecision, ConnID: "d", Timestamp: "2026-08-17T14:00:00Z"}}
	idx := BuildConcurrencyIndex([]Joined{
		denied,
		conn("a", "2026-08-17T14:00:00Z", 10_000),
	})
	if got := idx.At(at("2026-08-17T14:00:00Z"), "a"); got != 1 {
		t.Errorf("At = %d, want 1: a denial at the same instant is ambient context", got)
	}
	// ...but it does not persist, having no duration.
	if got := idx.At(at("2026-08-17T14:00:05Z"), "a"); got != 0 {
		t.Errorf("At = %d, want 0: a denial is an instant, not an interval", got)
	}
}

func TestConcurrencyIndex_EmptyLogIsZeroNotPanic(t *testing.T) {
	idx := BuildConcurrencyIndex(nil)
	if got := idx.At(at("2026-08-17T14:00:00Z"), ""); got != 0 {
		t.Errorf("At = %d, want 0", got)
	}
}

func TestConcurrencyIndex_SkipsUnparseableTimestamps(t *testing.T) {
	bad := conn("x", "not-a-time", 1000)
	idx := BuildConcurrencyIndex([]Joined{bad, conn("a", "2026-08-17T14:00:00Z", 10_000)})
	if got := idx.At(at("2026-08-17T14:00:05Z"), ""); got != 1 {
		t.Errorf("At = %d, want 1: the malformed record must be skipped, not counted", got)
	}
}

// A long-lived connection (an SSE stream, a websocket) must not be treated as
// permanently concurrent with everything after it in the log.
func TestConcurrencyIndex_LongConnectionEndsWhenItEnds(t *testing.T) {
	idx := BuildConcurrencyIndex([]Joined{
		conn("stream", "2026-08-17T14:00:00Z", 3_600_000), // one hour
	})
	if got := idx.At(at("2026-08-17T14:30:00Z"), ""); got != 1 {
		t.Errorf("At(mid-stream) = %d, want 1", got)
	}
	if got := idx.At(at("2026-08-17T15:30:00Z"), ""); got != 0 {
		t.Errorf("At(after close) = %d, want 0", got)
	}
}

func TestConcurrencyIndex_ScalesToALargeLog(t *testing.T) {
	base := at("2026-08-17T14:00:00Z")
	var js []Joined
	for i := 0; i < 50_000; i++ {
		js = append(js, conn("c"+strconv.Itoa(i),
			base.Add(time.Duration(i)*time.Second).Format(time.RFC3339), 5_000))
	}
	idx := BuildConcurrencyIndex(js)
	// Each connection lasts 5s and one starts per second, so ~5 overlap.
	got := idx.At(base.Add(1000*time.Second), "")
	if got < 3 || got > 7 {
		t.Errorf("At = %d, want roughly 5 overlapping", got)
	}
}
