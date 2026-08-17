package pending

import (
	"path/filepath"
	"testing"
)

func TestStore_RecordDedupesAndMergesHosts(t *testing.T) {
	p := filepath.Join(t.TempDir(), "pending.jsonl")
	s, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	base := Item{ExePath: "/usr/bin/git", OldSHA256: "old", NewSHA256: "new", Basename: "git", Hosts: []string{"github.com"}}
	if err := s.Record(base); err != nil {
		t.Fatal(err)
	}
	second := base
	second.Hosts = []string{"api.github.com"}
	if err := s.Record(second); err != nil {
		t.Fatal(err)
	}

	items, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("len(items) = %d, want 1 deduped item", len(items))
	}
	if items[0].Count != 2 {
		t.Errorf("Count = %d, want 2", items[0].Count)
	}
	if len(items[0].Hosts) != 2 {
		t.Errorf("Hosts = %v, want both hosts merged", items[0].Hosts)
	}
}

func TestStore_DifferentHashIsADifferentItem(t *testing.T) {
	p := filepath.Join(t.TempDir(), "pending.jsonl")
	s, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Record(Item{ExePath: "/usr/bin/git", NewSHA256: "aaa", Basename: "git"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Record(Item{ExePath: "/usr/bin/git", NewSHA256: "bbb", Basename: "git"}); err != nil {
		t.Fatal(err)
	}

	items, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Fatalf("len(items) = %d, want 2", len(items))
	}
}

func TestStore_ResolveRemoves(t *testing.T) {
	p := filepath.Join(t.TempDir(), "pending.jsonl")
	s, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Record(Item{ExePath: "/usr/bin/git", NewSHA256: "aaa", Basename: "git"}); err != nil {
		t.Fatal(err)
	}

	if err := s.Resolve("/usr/bin/git", "aaa"); err != nil {
		t.Fatal(err)
	}
	items, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Fatalf("len(items) = %d, want 0 after Resolve", len(items))
	}
}

func TestStore_RecordDoesNotResurrectExternallyResolvedItem(t *testing.T) {
	p := filepath.Join(t.TempDir(), "pending.jsonl")
	daemonStore, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := daemonStore.Record(Item{ExePath: "/usr/bin/git", NewSHA256: "aaa", Basename: "git"}); err != nil {
		t.Fatal(err)
	}
	reviewStore, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := reviewStore.Resolve("/usr/bin/git", "aaa"); err != nil {
		t.Fatal(err)
	}

	if err := daemonStore.Record(Item{ExePath: "/usr/bin/npm", NewSHA256: "bbb", Basename: "npm"}); err != nil {
		t.Fatal(err)
	}
	reloaded, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	items, err := reloaded.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("len(items) = %d, want only the new daemon observation", len(items))
	}
	if items[0].ExePath != "/usr/bin/npm" {
		t.Fatalf("resurrected externally resolved item: %+v", items)
	}
}

func TestStore_DistinctNewHashesCountsPathOnly(t *testing.T) {
	p := filepath.Join(t.TempDir(), "pending.jsonl")
	s, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range []Item{
		{ExePath: "/usr/bin/git", NewSHA256: "aaa", Basename: "git"},
		{ExePath: "/usr/bin/git", NewSHA256: "bbb", Basename: "git"},
		{ExePath: "/usr/bin/npm", NewSHA256: "ccc", Basename: "npm"},
	} {
		if err := s.Record(it); err != nil {
			t.Fatal(err)
		}
	}
	n, err := s.DistinctNewHashes("/usr/bin/git")
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("DistinctNewHashes(/usr/bin/git) = %d, want 2", n)
	}
}

func TestStore_SurvivesReopen(t *testing.T) {
	p := filepath.Join(t.TempDir(), "pending.jsonl")
	s, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Record(Item{ExePath: "/usr/bin/git", NewSHA256: "aaa", Basename: "git"}); err != nil {
		t.Fatal(err)
	}

	s2, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	items, err := s2.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("len(items) = %d after reopen, want 1", len(items))
	}
}

func TestCount_MatchesList(t *testing.T) {
	p := filepath.Join(t.TempDir(), "pending.jsonl")
	s, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Record(Item{ExePath: "/usr/bin/git", NewSHA256: "aaa", Basename: "git"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Record(Item{ExePath: "/usr/bin/npm", NewSHA256: "bbb", Basename: "npm"}); err != nil {
		t.Fatal(err)
	}

	n, err := Count(p)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("Count = %d, want 2", n)
	}
}

func TestCount_MissingFileIsZero(t *testing.T) {
	n, err := Count(filepath.Join(t.TempDir(), "nope.jsonl"))
	if err != nil {
		t.Fatalf("missing file should not be an error: %v", err)
	}
	if n != 0 {
		t.Errorf("Count = %d, want 0", n)
	}
}
