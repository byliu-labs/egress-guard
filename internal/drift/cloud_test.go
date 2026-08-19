package drift

import (
	"fmt"
	"testing"

	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/decisionlog"
)

func flowPair(connID, timestamp, exe, host string, bytesUp int64, decision decisionlog.Decision) []decisionlog.Entry {
	yes := true
	return []decisionlog.Entry{
		{Kind: decisionlog.KindDecision, ConnID: connID, Timestamp: timestamp, Exe: exe, Host: host, Decision: decision, UserActive: &yes},
		{Kind: decisionlog.KindFlow, ConnID: connID, Timestamp: timestamp, BytesUp: bytesUp, BytesDown: 100, DurationMS: 50},
	}
}

func TestBuildBaselineHistoricalPointsCarryConcurrency(t *testing.T) {
	var entries []decisionlog.Entry
	for i, timestamp := range []string{
		"2026-08-17T14:00:00Z", "2026-08-17T14:00:01Z", "2026-08-17T14:00:02Z",
	} {
		entries = append(entries, flowPair(fmt.Sprintf("c%d", i), timestamp, "/usr/bin/git", "github.com", 1000, decisionlog.DecisionAllow)...)
		entries[len(entries)-1].DurationMS = 60_000
	}
	baseline := BuildBaseline(&catalog.Catalog{}, entries)
	cloud, _ := baseline.CloudFor(catalog.Identity{ExeBasename: "git"}, "github.com")
	if len(cloud) != 3 {
		t.Fatalf("cloud has %d points, want 3", len(cloud))
	}
	if cloud[2][DimConcurrency] <= cloud[0][DimConcurrency] {
		t.Errorf("the third overlapping connection saw concurrency %v, the first saw %v; the later one must see more", cloud[2][DimConcurrency], cloud[0][DimConcurrency])
	}
}

func TestBaselinePairsIncludesFlowlessDecision(t *testing.T) {
	entry := decisionlog.Entry{
		Kind:      decisionlog.KindDecision,
		ConnID:    "open",
		Timestamp: "2026-08-17T14:00:00Z",
		Decision:  decisionlog.DecisionAllow,
		Exe:       "/usr/bin/git",
		Host:      "github.com",
	}

	pairs := BuildBaseline(&catalog.Catalog{}, []decisionlog.Entry{entry}).Pairs()
	if len(pairs) != 1 {
		t.Fatalf("Pairs() returned %d pairs, want 1", len(pairs))
	}
	if pairs[0].Host != entry.Host {
		t.Errorf("Pairs()[0].Host = %q, want %q", pairs[0].Host, entry.Host)
	}
	if pairs[0].Identity.ExeBasename != "git" {
		t.Errorf("Pairs()[0].Identity.ExeBasename = %q, want git", pairs[0].Identity.ExeBasename)
	}
}

func TestBaselinePairsSurviveSaveAndLoad(t *testing.T) {
	entries := flowPair("a", "2026-08-17T14:00:00Z", "/usr/bin/git", "github.com", 1, decisionlog.DecisionAllow)
	path := t.TempDir() + "/baseline.json"
	if err := BuildBaseline(&catalog.Catalog{}, entries).Save(path); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadBaseline(path, &catalog.Catalog{})
	if err != nil {
		t.Fatal(err)
	}
	pairs := loaded.Pairs()
	if len(pairs) != 1 {
		t.Fatalf("loaded Pairs() returned %d pairs, want 1", len(pairs))
	}
	if pairs[0].Host != "github.com" || pairs[0].Identity.ExeBasename != "git" {
		t.Fatalf("loaded pair = %+v, want git -> github.com", pairs[0])
	}
}

func TestBuildBaselineAccumulatesSeparatedAndUnpoisonedClouds(t *testing.T) {
	entries := append(flowPair("a1", "2026-08-17T14:00:00Z", "/usr/bin/git", "github.com", 1, decisionlog.DecisionAllow), flowPair("b1", "2026-08-17T14:01:00Z", "/usr/bin/curl", "evil.example", 2, decisionlog.DecisionDeny)...)
	entries = append(entries, flowPair("a2", "2026-08-17T14:01:00Z", "/usr/bin/git", "github.com", 3, decisionlog.DecisionAllow)...)
	baseline := BuildBaseline(&catalog.Catalog{}, entries)
	git, _ := baseline.CloudFor(catalog.Identity{ExeBasename: "git"}, "github.com")
	evil, _ := baseline.CloudFor(catalog.Identity{ExeBasename: "curl"}, "evil.example")
	if len(git) != 2 || len(evil) != 0 {
		t.Fatalf("git=%d evil=%d", len(git), len(evil))
	}
	if got := git[1][DimInterArrival]; got < 4 || got > 4.2 {
		t.Fatalf("pair-local gap = %v", got)
	}
}

func TestBaselineCloudsSurviveSaveAndLoad(t *testing.T) {
	entries := append(flowPair("a1", "2026-08-17T14:00:00Z", "/usr/bin/git", "github.com", 1, decisionlog.DecisionAllow), flowPair("a2", "2026-08-18T14:00:00Z", "/usr/bin/git", "github.com", 2, decisionlog.DecisionAllow)...)
	path := t.TempDir() + "/baseline.json"
	if err := BuildBaseline(&catalog.Catalog{}, entries).Save(path); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadBaseline(path, &catalog.Catalog{})
	if err != nil {
		t.Fatal(err)
	}
	cloud, _ := loaded.CloudFor(catalog.Identity{ExeBasename: "git"}, "github.com")
	if len(cloud) != 2 {
		t.Fatalf("loaded cloud = %d", len(cloud))
	}
}
