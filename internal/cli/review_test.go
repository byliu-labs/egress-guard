package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/pending"
)

func TestReviewApproveAll_PinsNewHashAndDrainsQueue(t *testing.T) {
	dir := t.TempDir()
	pendingPath := filepath.Join(dir, "pending.jsonl")
	catalogPath := filepath.Join(dir, "user.toml")

	store, err := pending.Open(pendingPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Record(pending.Item{
		ExePath:   "/usr/bin/git",
		Basename:  "git",
		OldSHA256: strings.Repeat("a", 64),
		NewSHA256: strings.Repeat("b", 64),
		Hosts:     []string{"github.com"},
	}); err != nil {
		t.Fatal(err)
	}

	if err := approveAll(store, newCatalogRatifyWriter(catalogPath, nil)); err != nil {
		t.Fatalf("approveAll: %v", err)
	}

	left, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 {
		t.Errorf("queue still has %d items", len(left))
	}

	cat, err := catalog.LoadFile(catalogPath)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	got := cat.Lookup(catalog.Identity{
		ExeBasename: "git",
		ExePath:     "/usr/bin/git",
		ExeSHA256:   strings.Repeat("b", 64),
	}, "github.com")
	if !got.Found {
		t.Fatal("the approved binary was not pinned")
	}
}

func TestReviewPinnedMessageSaysDaemonReloadRequired(t *testing.T) {
	msg := reviewPinnedMessage(1)
	lower := strings.ToLower(msg)
	if !strings.Contains(lower, "restart") {
		t.Fatalf("message = %q, want explicit restart requirement", msg)
	}
	if strings.Contains(lower, "will no longer prompt") {
		t.Fatalf("message = %q, must not claim a running daemon sees reviewed pins immediately", msg)
	}
}
