package drift

import (
	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/decisionlog"
	"testing"
)

type rejectHost string

func (r rejectHost) Contains(_, _, _, host string) bool { return host == string(r) }
func (r rejectHost) Digest() string                     { return string(r) }

func TestBuildBaselineRejectedPairIsAbsentFromMembershipAndClouds(t *testing.T) {
	entries := []decisionlog.Entry{learnedEntry("2026-08-01T00:00:00Z", "/bin/curl", "evil.example"), learnedEntry("2026-08-02T00:00:00Z", "/bin/curl", "evil.example"), learnedEntry("2026-08-02T00:00:00Z", "/bin/git", "github.com")}
	b := BuildBaselineWithRejections(&catalog.Catalog{}, entries, rejectHost("evil.example"))
	if got := b.Classify(learnedEntry("2026-08-03T00:00:00Z", "/bin/curl", "evil.example")); got.Class != ClassDrift {
		t.Fatalf("Classify = %+v", got)
	}
	for _, p := range b.Pairs() {
		if p.Host == "evil.example" {
			t.Fatal("rejected pair remains in cloud")
		}
	}
	for _, p := range b.Learned() {
		if p.Host == "evil.example" {
			t.Fatal("rejected pair remains in provenance")
		}
	}
}

func TestRejectedLatestEntryDoesNotMakeCacheForeverStale(t *testing.T) {
	entries := []decisionlog.Entry{learnedEntry("2026-08-01T00:00:00Z", "/bin/git", "github.com"), learnedEntry("2026-08-02T00:00:00Z", "/bin/curl", "evil.example")}
	b := BuildBaselineWithRejections(nil, entries, rejectHost("evil.example"))
	if b.IsStale(entries) {
		t.Fatal("same log is stale because rejected latest entry did not advance cursor")
	}
}
