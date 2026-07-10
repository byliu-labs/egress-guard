package reviewqueue

import (
	"testing"
	"time"

	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/telemetry"
)

func newTestCatalog(t *testing.T) *catalog.Catalog {
	t.Helper()
	cat, err := catalog.Load(nil)
	if err != nil {
		t.Fatalf("catalog.Load(nil): %v", err)
	}
	return cat
}

func TestApprove_RequiresEvidence_HighFrequencyAloneCannotPromote(t *testing.T) {
	q := New()
	id := catalog.Identity{ExeBasename: "evilctl", TeamID: "SYBIL0001"}
	for i := 0; i < 500; i++ {
		uuid := string(rune('a'+i%26)) + string(rune('0'+i/26))
		q.Ingest(telemetry.NewReport(uuid, id, "evil.example.com", "allow"))
	}
	key := Key{Identity: id, Host: "evil.example.com", Verdict: "allow"}
	cat := newTestCatalog(t)

	_, err := q.Approve(cat, key)
	if err == nil {
		t.Fatal("Approve: want error for a candidate with no Evidence, got nil")
	}

	result := cat.Lookup(id, "evil.example.com")
	if result.Found {
		t.Fatal("catalog.Lookup: Found = true after rejected Approve")
	}
}

func TestApprove_SucceedsWithEvidenceAndConfidence(t *testing.T) {
	q := New()
	id := catalog.Identity{ExeBasename: "curl", TeamID: "REALDEV001"}
	q.Ingest(telemetry.NewReport("uuid-1", id, "api.example.com", "allow"))
	key := Key{Identity: id, Host: "api.example.com", Verdict: "allow"}

	if err := q.SetEvidence(key, "notarized Developer ID, verified via codesign -dv", catalog.ConfidenceHigh); err != nil {
		t.Fatalf("SetEvidence: %v", err)
	}
	cat := newTestCatalog(t)
	entry, err := q.Approve(cat, key)
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if entry.Layer != "baseline" {
		t.Fatalf("Layer = %q, want baseline", entry.Layer)
	}
	if entry.Evidence == "" {
		t.Fatal("Evidence empty on promoted entry")
	}
	if !cat.Lookup(id, "api.example.com").Found {
		t.Fatal("catalog.Lookup: Found = false after successful Approve")
	}
	if q.Candidates()[0].Status != StatusApproved {
		t.Fatalf("Status = %q, want %q", q.Candidates()[0].Status, StatusApproved)
	}
}

func TestApprove_DenyVerdictWritesNeverEntry(t *testing.T) {
	q := New()
	id := catalog.Identity{ExeBasename: "curl", TeamID: "REALDEV001"}
	q.Ingest(telemetry.NewReport("uuid-1", id, "evil.example.com", "deny"))
	key := Key{Identity: id, Host: "evil.example.com", Verdict: "deny"}
	q.SetEvidence(key, "known malware C2 domain, confirmed via VirusTotal", catalog.ConfidenceHigh)

	cat := newTestCatalog(t)
	entry, err := q.Approve(cat, key)
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if len(entry.Never) != 1 || entry.Never[0] != "evil.example.com" {
		t.Fatalf("Never = %v, want [evil.example.com]", entry.Never)
	}
}

func TestApprove_EvenWhenBurstFlagged_StillRequiresEvidenceButCanSucceed(t *testing.T) {
	q := New()
	id := catalog.Identity{ExeBasename: "curl", TeamID: "REALDEV001"}
	for i := 0; i < 10; i++ {
		uuid := string(rune('a' + i))
		q.Ingest(telemetry.NewReport(uuid, id, "api.example.com", "allow"))
	}
	key := Key{Identity: id, Host: "api.example.com", Verdict: "allow"}
	q.DetectBursts(5, time.Hour)

	cat := newTestCatalog(t)
	if _, err := q.Approve(cat, key); err == nil {
		t.Fatal("Approve: want error with no evidence, even though burst-flagged")
	}

	q.SetEvidence(key, "maintainer manually verified this is Homebrew's real curl update endpoint", catalog.ConfidenceHigh)
	if _, err := q.Approve(cat, key); err != nil {
		t.Fatalf("Approve after genuine evidence: %v", err)
	}
}

func TestReject_MarksStatusRejected(t *testing.T) {
	q := New()
	id := catalog.Identity{ExeBasename: "evilctl"}
	q.Ingest(telemetry.NewReport("uuid-1", id, "evil.example.com", "allow"))
	key := Key{Identity: id, Host: "evil.example.com", Verdict: "allow"}

	if err := q.Reject(key, "known Sybil pattern, no independent evidence"); err != nil {
		t.Fatalf("Reject: %v", err)
	}
	if q.Candidates()[0].Status != StatusRejected {
		t.Fatalf("Status = %q, want %q", q.Candidates()[0].Status, StatusRejected)
	}
}
