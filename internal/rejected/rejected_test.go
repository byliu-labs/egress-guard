package rejected

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRejectPersistsAndChangesDigest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rejected-pairs.jsonl")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	empty := s.Digest()
	key := Key{ExeBasename: "curl", Host: "evil.example"}
	if err := s.Reject(key, "unrecognized"); err != nil {
		t.Fatal(err)
	}
	if s.Digest() == empty || !s.Contains(key) {
		t.Fatal("rejection did not change set")
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reopened.Contains(key) || reopened.Digest() != s.Digest() {
		t.Fatal("rejection not durable")
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("file privacy: %v %v", info, err)
	}
	if err := reopened.Restore(key); err != nil {
		t.Fatal(err)
	}
	if reopened.Contains(key) || reopened.Digest() != empty {
		t.Fatal("restore did not undo rejection")
	}
}

func TestRejectDoesNotMatchOtherPair(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "rejected-pairs.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Reject(Key{ExeBasename: "curl", Host: "evil.example"}, ""); err != nil {
		t.Fatal(err)
	}
	if s.Contains(Key{ExeBasename: "git", Host: "evil.example"}) || s.Contains(Key{ExeBasename: "curl", Host: "other.example"}) {
		t.Fatal("rejection matched another pair")
	}
}

func TestRejectionMatchesBaselineHostCaseFolding(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "rejected.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Reject(Key{ExeBasename: "curl", Host: "Evil.Example"}, ""); err != nil {
		t.Fatal(err)
	}
	if !s.Contains(Key{ExeBasename: "curl", Host: "evil.example"}) {
		t.Fatal("same baseline host bucket escaped rejection through case")
	}
}

func TestOpenQuarantinesCorruptStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rejected.jsonl")
	if err := os.WriteFile(path, []byte("{bad json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".corrupt"); err != nil {
		t.Fatal(err)
	}
	if !s.Quarantined() {
		t.Fatal("daemon would treat unknown rejection set as empty")
	}
}

func TestOpenReadOnlyLeavesCorruptFileUntouched(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rejected.jsonl")
	if err := os.WriteFile(path, []byte("{bad json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenReadOnly(path); err == nil {
		t.Fatal("calibration accepted corrupt rejection set")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("calibration moved source file", err)
	}
}

func TestTwoStoreInstancesPreserveSequentialDecisions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rejected.jsonl")
	a, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	first := Key{ExeBasename: "curl", Host: "a.example"}
	second := Key{ExeBasename: "git", Host: "b.example"}
	if err := a.Reject(first, ""); err != nil {
		t.Fatal(err)
	}
	if err := b.Reject(second, ""); err != nil {
		t.Fatal(err)
	}
	read, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if !read.Contains(first) || !read.Contains(second) {
		t.Fatal("second writer clobbered first decision")
	}
}

func TestQuarantineSurvivesReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rejected.jsonl")
	if err := os.WriteFile(path, []byte("{bad json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reopened.Quarantined() {
		t.Fatal("restart forgot corrupt rejection history")
	}
}
