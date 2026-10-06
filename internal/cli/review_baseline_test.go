package cli

import (
	"bytes"
	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/drift"
	"github.com/byliu-labs/egress-guard/internal/rejected"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBaselineReviewQuotesHostAndRejectsSelectedPair(t *testing.T) {
	pair := drift.LearnedPair{Identity: catalog.Identity{ExeBasename: "curl"}, Host: "evil.example\n$(touch /tmp/should-not-run)", FirstSeen: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC), Count: 2}
	var out bytes.Buffer
	renderBaselineReview(&out, []drift.LearnedPair{pair})
	if !strings.Contains(out.String(), "1.") || strings.Contains(out.String(), "\n$(touch") {
		t.Fatalf("unsafe or unnumbered review: %q", out.String())
	}
	store, err := rejected.Open(filepath.Join(t.TempDir(), "rejected.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if err := rejectByIndex(store, []drift.LearnedPair{pair}, 1, "unknown"); err != nil {
		t.Fatal(err)
	}
	if !store.Contains(rejected.Key{ExeBasename: "curl", Host: pair.Host}) {
		t.Fatal("selected pair not rejected")
	}
	if err := rejectByIndex(store, []drift.LearnedPair{pair}, 2, ""); err == nil {
		t.Fatal("out of range selection accepted")
	}
}
