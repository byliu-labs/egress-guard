package reviewqueue

import (
	"fmt"
	"testing"

	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/telemetry"
)

func syntheticReport(uuid string) telemetry.Report {
	return telemetry.NewReport(uuid, catalog.Identity{ExeBasename: "evilctl", TeamID: "SYBIL0001"}, "evil.example.com", "allow")
}

func TestFloodOfIdenticalRatifications_ProducesOneQueuedCandidate(t *testing.T) {
	q := New()
	const floodSize = 200
	for i := 0; i < floodSize; i++ {
		if err := q.Ingest(syntheticReport(fmt.Sprintf("sybil-%03d", i))); err != nil {
			t.Fatalf("Ingest(%d): %v", i, err)
		}
	}

	cands := q.Candidates()
	if len(cands) != 1 {
		t.Fatalf("len(Candidates()) = %d, want 1", len(cands))
	}
	c := cands[0]
	if c.Count != floodSize {
		t.Fatalf("Count = %d, want %d", c.Count, floodSize)
	}
	if c.Status != StatusQueued {
		t.Fatalf("Status = %q, want %q", c.Status, StatusQueued)
	}
}

func TestIngest_DifferentVerdictsAreDifferentCandidates(t *testing.T) {
	q := New()
	allow := telemetry.NewReport("u1", catalog.Identity{ExeBasename: "curl"}, "api.example.com", "allow")
	deny := telemetry.NewReport("u2", catalog.Identity{ExeBasename: "curl"}, "api.example.com", "deny")
	if err := q.Ingest(allow); err != nil {
		t.Fatalf("Ingest allow: %v", err)
	}
	if err := q.Ingest(deny); err != nil {
		t.Fatalf("Ingest deny: %v", err)
	}
	if len(q.Candidates()) != 2 {
		t.Fatalf("len(Candidates()) = %d, want 2", len(q.Candidates()))
	}
}

func TestCandidates_OrderedByCountDescending(t *testing.T) {
	q := New()
	low := telemetry.NewReport("u1", catalog.Identity{ExeBasename: "low"}, "low.example.com", "allow")
	high := telemetry.NewReport("u2", catalog.Identity{ExeBasename: "high"}, "high.example.com", "allow")
	q.Ingest(low)
	q.Ingest(high)
	q.Ingest(high)
	q.Ingest(high)

	cands := q.Candidates()
	if cands[0].Key.Host != "high.example.com" || cands[0].Count != 3 {
		t.Fatalf("Candidates()[0] = %+v, want the higher-frequency candidate first", cands[0])
	}
	if cands[1].Key.Host != "low.example.com" || cands[1].Count != 1 {
		t.Fatalf("Candidates()[1] = %+v, want the lower-frequency candidate last", cands[1])
	}
}

func TestCandidate_DistinctUUIDs(t *testing.T) {
	q := New()
	q.Ingest(syntheticReport("uuid-a"))
	q.Ingest(syntheticReport("uuid-a"))
	q.Ingest(syntheticReport("uuid-b"))

	c := q.Candidates()[0]
	if c.Count != 3 {
		t.Fatalf("Count = %d, want 3", c.Count)
	}
	if got := c.DistinctUUIDs(); got != 2 {
		t.Fatalf("DistinctUUIDs() = %d, want 2", got)
	}
}
