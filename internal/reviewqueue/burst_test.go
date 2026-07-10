package reviewqueue

import (
	"testing"
	"time"

	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/telemetry"
)

func TestDetectBursts_FlagsCoordinatedBurst_WithoutAutoActioning(t *testing.T) {
	q := New()
	for i := 0; i < 10; i++ {
		uuid := string(rune('a' + i))
		q.Ingest(telemetry.NewReport(uuid, catalog.Identity{ExeBasename: "evilctl"}, "evil.example.com", "allow"))
	}

	q.DetectBursts(5, time.Hour)

	c := q.Candidates()[0]
	if !c.Burst {
		t.Fatal("Burst = false, want true")
	}
	if c.Status != StatusQueued {
		t.Fatalf("Status = %q, want %q", c.Status, StatusQueued)
	}
}

func TestDetectBursts_BelowThresholdNotFlagged(t *testing.T) {
	q := New()
	for i := 0; i < 3; i++ {
		uuid := string(rune('a' + i))
		q.Ingest(telemetry.NewReport(uuid, catalog.Identity{ExeBasename: "normalapp"}, "cdn.example.com", "allow"))
	}

	q.DetectBursts(5, time.Hour)

	c := q.Candidates()[0]
	if c.Burst {
		t.Fatal("Burst = true, want false")
	}
}

func TestDetectBursts_OutsideWindowNotCounted(t *testing.T) {
	q := New()
	old := time.Now().Add(-48 * time.Hour)
	for i := 0; i < 10; i++ {
		uuid := string(rune('a' + i))
		q.mu.Lock()
		q.ingestLocked(telemetry.NewReport(uuid, catalog.Identity{ExeBasename: "evilctl"}, "evil.example.com", "allow"), old, false)
		q.mu.Unlock()
	}
	q.Ingest(telemetry.NewReport("recent", catalog.Identity{ExeBasename: "evilctl"}, "evil.example.com", "allow"))

	q.DetectBursts(5, time.Hour)

	c := q.Candidates()[0]
	if c.Burst {
		t.Fatal("Burst = true, want false")
	}
}
