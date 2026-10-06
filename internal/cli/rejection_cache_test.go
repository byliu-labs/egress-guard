package cli

import (
	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/drift"
	"github.com/byliu-labs/egress-guard/internal/rejected"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrBuildBaselineRebuildsWhenRejectionsChange(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "blocked.log")
	cachePath := filepath.Join(dir, "baseline.json")
	writeLog(t, logPath, twoDayPair("/usr/bin/curl", "evil.example"))
	store, err := rejected.Open(filepath.Join(dir, "rejected-pairs.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	load := func() *drift.Baseline {
		t.Helper()
		b, err := loadOrBuildBaseline(logPath, cachePath, &catalog.Catalog{}, nil, rejectionAdapter{s: store})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	if len(load().Pairs()) != 1 {
		t.Fatal("expected cloud before rejection")
	}
	if err := store.Reject(rejected.Key{ExeBasename: "curl", Host: "evil.example"}, "unexpected"); err != nil {
		t.Fatal(err)
	}
	if b := load(); len(b.Pairs()) != 0 || len(b.Learned()) != 0 {
		t.Fatalf("cached pair survived rejection: pairs=%+v learned=%+v", b.Pairs(), b.Learned())
	}
	if err := store.Restore(rejected.Key{ExeBasename: "curl", Host: "evil.example"}); err != nil {
		t.Fatal(err)
	}
	if len(load().Pairs()) != 1 {
		t.Fatal("restored pair was not rebuilt")
	}
}

func TestCorruptRejectionStoreDisablesBaseline(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rejected.jsonl")
	if err := os.WriteFile(path, []byte("{bad json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := rejected.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrBuildBaseline(filepath.Join(dir, "blocked.log"), filepath.Join(dir, "baseline.json"), nil, nil, rejectionAdapter{s: store}); err == nil {
		t.Fatal("corrupt rejection set would silently relearn pairs")
	}
}
