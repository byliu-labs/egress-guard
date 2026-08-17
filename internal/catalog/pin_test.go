package catalog

import (
	"strings"
	"testing"
)

func pinnedEntry(t *testing.T, path, sum string) *Catalog {
	t.Helper()
	c := &Catalog{}
	if err := c.Add(Entry{
		SchemaVersion:        CurrentSchemaVersion,
		Identity:             Identity{ExeBasename: "git", ExePath: path, ExeSHA256: sum},
		ExpectedDestinations: []Destination{{Host: "github.com", Why: "fixture"}},
		Explanation:          "git talks to github",
		Evidence:             "fixture",
		Confidence:           ConfidenceMedium,
		Layer:                "user",
	}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	return c
}

func TestLookup_PinnedEntryMatchesExactBinary(t *testing.T) {
	sum := strings.Repeat("a", 64)
	c := pinnedEntry(t, "/usr/bin/git", sum)

	got := c.Lookup(Identity{ExeBasename: "git", ExePath: "/usr/bin/git", ExeSHA256: sum}, "github.com")

	if !got.Found {
		t.Fatal("pinned entry did not match its own binary")
	}
}

func TestLookup_PinnedEntryRejectsSwappedBinary(t *testing.T) {
	c := pinnedEntry(t, "/usr/bin/git", strings.Repeat("a", 64))

	got := c.Lookup(Identity{ExeBasename: "git", ExePath: "/usr/bin/git", ExeSHA256: strings.Repeat("b", 64)}, "github.com")

	if got.Found {
		t.Fatal("pinned entry matched a different binary at the same path")
	}
}

func TestLookup_PinnedEntryRejectsImpostorPath(t *testing.T) {
	sum := strings.Repeat("a", 64)
	c := pinnedEntry(t, "/usr/bin/git", sum)

	got := c.Lookup(Identity{ExeBasename: "git", ExePath: "/tmp/git", ExeSHA256: sum}, "github.com")

	if got.Found {
		t.Fatal("pinned entry matched a binary at a different path")
	}
}

func TestLookup_PinnedEntryRejectsUnhashedProcess(t *testing.T) {
	c := pinnedEntry(t, "/usr/bin/git", strings.Repeat("a", 64))

	got := c.Lookup(Identity{ExeBasename: "git", ExePath: "/usr/bin/git"}, "github.com")

	if got.Found {
		t.Fatal("pinned entry matched a process whose hash could not be computed")
	}
}

func TestHasDecisionPin_RequiresUsableBindingStrength(t *testing.T) {
	cases := []struct {
		name string
		id   Identity
		want bool
	}{
		{"basename only", Identity{ExeBasename: "git"}, false},
		{"hash without path", Identity{ExeBasename: "git", ExeSHA256: strings.Repeat("a", 64)}, false},
		{"pinned binary", Identity{ExeBasename: "git", ExePath: "/usr/bin/git", ExeSHA256: strings.Repeat("a", 64)}, true},
		{"team id", Identity{ExeBasename: "Slack", TeamID: "T1234"}, true},
		{"bundle id", Identity{ExeBasename: "Slack", BundleID: "com.slack"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := HasDecisionPin(tc.id); got != tc.want {
				t.Fatalf("HasDecisionPin = %v, want %v", got, tc.want)
			}
		})
	}
}
