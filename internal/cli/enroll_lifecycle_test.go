package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/daemon"
	"github.com/byliu-labs/egress-guard/internal/pending"
	"github.com/byliu-labs/egress-guard/internal/procid"
)

func TestEnrollUpgradeReview_NeverPromptsMidWork(t *testing.T) {
	dir := t.TempDir()
	catalogPath := filepath.Join(dir, "user.toml")
	pendingPath := filepath.Join(dir, "pending.jsonl")

	interp := filepath.Join(dir, "node")
	if err := os.WriteFile(interp, []byte("node v1"), 0o755); err != nil {
		t.Fatal(err)
	}
	shim := filepath.Join(dir, "npm")
	if err := os.WriteFile(shim, []byte("#!"+interp+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	baseline := &catalog.Catalog{}
	if err := baseline.Add(catalog.Entry{
		SchemaVersion:        catalog.CurrentSchemaVersion,
		Identity:             catalog.Identity{ExeBasename: "npm"},
		ExpectedDestinations: []catalog.Destination{{Host: "registry.npmjs.org", Why: "registry"}},
		Explanation:          "npm downloads Node packages.",
		Evidence:             "fixture",
		Confidence:           catalog.ConfidenceMedium,
		Layer:                "baseline",
	}); err != nil {
		t.Fatal(err)
	}

	found := scanCatalogTools(baseline, func(name string) (string, error) {
		if name == "npm" {
			return shim, nil
		}
		return "", exec.ErrNotFound
	})
	if len(found) != 1 {
		t.Fatalf("enroll found %d tools, want 1", len(found))
	}
	wantInterp, err := filepath.EvalSymlinks(interp)
	if err != nil {
		t.Fatal(err)
	}
	if found[0].ExePath != wantInterp {
		t.Fatalf("enroll pinned %q, want the interpreter %q", found[0].ExePath, wantInterp)
	}
	w := newCatalogRatifyWriter(catalogPath, nil)
	for _, h := range found[0].Hosts {
		if err := w.Ratify(enrollEntry(found[0], h, time.Now().Format("2006-01-02"))); err != nil {
			t.Fatalf("ratify: %v", err)
		}
	}

	userCat, err := catalog.LoadFile(catalogPath)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	store, err := pending.Open(pendingPath)
	if err != nil {
		t.Fatal(err)
	}
	hasher := procid.NewExeHasher()

	decide := func() (bool, string, bool) {
		allowed, reason, prompted, err := daemon.DecideForTest(userCat, store, hasher, wantInterp, "registry.npmjs.org")
		if err != nil {
			t.Fatalf("DecideForTest: %v", err)
		}
		return allowed, reason, prompted
	}

	allowed, _, prompted := decide()
	if !allowed || prompted {
		t.Fatalf("after enroll: allowed=%v prompted=%v, want allowed with no prompt", allowed, prompted)
	}
	if n, err := pending.Count(pendingPath); err != nil || n != 0 {
		t.Fatalf("queue after enrolling = %d, %v; want 0, nil", n, err)
	}

	if err := os.WriteFile(interp, []byte("node v2 -- upgraded, different length"), 0o755); err != nil {
		t.Fatal(err)
	}

	allowed, reason, prompted := decide()
	if !allowed {
		t.Fatal("an upgraded binary blocked work")
	}
	if prompted {
		t.Fatal("an upgraded binary interrupted work with a prompt")
	}
	if reason != "unratified_binary_grace" {
		t.Fatalf("reason = %q, want unratified_binary_grace", reason)
	}
	if n, err := pending.Count(pendingPath); err != nil || n != 1 {
		t.Fatalf("queue after upgrade = %d, %v; want 1, nil", n, err)
	}

	if err := approveAll(store, newCatalogRatifyWriter(catalogPath, nil)); err != nil {
		t.Fatalf("approveAll: %v", err)
	}
	if n, err := pending.Count(pendingPath); err != nil || n != 0 {
		t.Fatalf("queue after review = %d, %v; want 0, nil", n, err)
	}

	userCat, err = catalog.LoadFile(catalogPath)
	if err != nil {
		t.Fatal(err)
	}
	allowed, reason, prompted = decide()
	if !allowed || prompted {
		t.Fatalf("after review: allowed=%v prompted=%v, want a clean silent allow", allowed, prompted)
	}
	if reason == "unratified_binary_grace" {
		t.Fatal("still on the grace path after review; the new hash was not pinned")
	}
	if strings.Contains(reason, "prompt") {
		t.Fatalf("reason = %q, want a catalog-backed allow", reason)
	}
}
