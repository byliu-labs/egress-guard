package catalog

import (
	"strings"
	"testing"
)

func pinned(t *testing.T, path, sum, host string) *Catalog {
	t.Helper()
	c := &Catalog{}
	if err := c.Add(Entry{
		SchemaVersion:        CurrentSchemaVersion,
		Identity:             Identity{ExeBasename: "git", ExePath: path, ExeSHA256: sum},
		ExpectedDestinations: []Destination{{Host: host, Why: "fixture"}},
		Explanation:          "git talks to github",
		Evidence:             "fixture",
		Confidence:           ConfidenceMedium,
		Layer:                "user",
	}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	return c
}

func pinnedWithNever(t *testing.T, path, sum, allowHost, neverHost string) *Catalog {
	t.Helper()
	c := &Catalog{}
	if err := c.Add(Entry{
		SchemaVersion:        CurrentSchemaVersion,
		Identity:             Identity{ExeBasename: "git", ExePath: path, ExeSHA256: sum},
		ExpectedDestinations: []Destination{{Host: allowHost, Why: "fixture"}},
		Never:                []string{neverHost},
		Explanation:          "git talks to github",
		Evidence:             "fixture",
		Confidence:           ConfidenceMedium,
		Layer:                "user",
	}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	return c
}

func TestLookup_StaleBinarySignalledNotMatched(t *testing.T) {
	old := strings.Repeat("a", 64)
	c := pinned(t, "/usr/bin/git", old, "github.com")

	got := c.Lookup(Identity{ExeBasename: "git", ExePath: "/usr/bin/git", ExeSHA256: strings.Repeat("b", 64)}, "github.com")

	if got.Found {
		t.Fatal("a stale binary must not count as Found")
	}
	if !got.StaleBinary {
		t.Fatal("expected StaleBinary for a same-path different-hash pin")
	}
	if got.Entry.Identity.ExeSHA256 != old {
		t.Errorf("Entry should carry the stale pin, got %q", got.Entry.Identity.ExeSHA256)
	}
}

func TestLookup_StaleBinaryOnlyForKnownHost(t *testing.T) {
	c := pinned(t, "/usr/bin/git", strings.Repeat("a", 64), "github.com")

	got := c.Lookup(Identity{ExeBasename: "git", ExePath: "/usr/bin/git", ExeSHA256: strings.Repeat("b", 64)}, "evil.example")

	if got.StaleBinary {
		t.Fatal("grace must not extend to a host the path was never ratified for")
	}
}

func TestLookup_StaleBinaryPreservesNeverHit(t *testing.T) {
	c := pinnedWithNever(t, "/usr/bin/git", strings.Repeat("a", 64), "github.com", "evil.example")

	got := c.Lookup(Identity{ExeBasename: "git", ExePath: "/usr/bin/git", ExeSHA256: strings.Repeat("b", 64)}, "evil.example")

	if !got.NeverHit {
		t.Fatal("a changed binary at the same path must still hit explicit never destinations")
	}
	if got.StaleBinary && !got.Found {
		t.Fatal("never must dominate stale grace, not fall through as an unowned stale allow")
	}
}

func TestLookup_DifferentPathIsNotStale(t *testing.T) {
	sum := strings.Repeat("a", 64)
	c := pinned(t, "/usr/bin/git", sum, "github.com")

	got := c.Lookup(Identity{ExeBasename: "git", ExePath: "/tmp/git", ExeSHA256: strings.Repeat("b", 64)}, "github.com")

	if got.StaleBinary {
		t.Fatal("a different path is a different program, not a stale binary")
	}
}
