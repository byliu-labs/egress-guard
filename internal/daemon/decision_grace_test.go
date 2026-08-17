package daemon

import (
	"errors"
	"strings"
	"testing"

	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/decisionlog"
	"github.com/byliu-labs/egress-guard/internal/pending"
	"github.com/byliu-labs/egress-guard/internal/procid"
	"github.com/byliu-labs/egress-guard/internal/signature"
)

type recordingPending struct {
	items          []pending.Item
	distinctHashes int
}

func (r *recordingPending) Record(it pending.Item) error {
	r.items = append(r.items, it)
	return nil
}

func (r *recordingPending) DistinctNewHashes(string) (int, error) {
	return r.distinctHashes, nil
}

type failingPending struct{}

func (failingPending) Record(pending.Item) error {
	return errors.New("no space left on device")
}

func (failingPending) DistinctNewHashes(string) (int, error) {
	return 0, nil
}

func gitPinCatalog(t *testing.T, host string) *catalog.Catalog {
	t.Helper()
	c := &catalog.Catalog{}
	if err := c.Add(catalog.Entry{
		SchemaVersion:        catalog.CurrentSchemaVersion,
		Identity:             catalog.Identity{ExeBasename: "git", ExePath: "/usr/bin/git", ExeSHA256: strings.Repeat("a", 64)},
		ExpectedDestinations: []catalog.Destination{{Host: host, Why: "fixture"}},
		Explanation:          "git talks to github",
		Evidence:             "fixture",
		Confidence:           catalog.ConfidenceMedium,
		Layer:                "user",
	}); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestDecideBranch_StaleBinaryAllowsAndQueues(t *testing.T) {
	rec := &recordingPending{}
	dec := &capturingDecider{}
	d := newDaemonForBranchWithCatalog(t, dec, gitPinCatalog(t, "github.com"))
	d.opts.Pending = rec

	outcome, entry := d.decideBranchWithIdentity(
		"github.com", nil,
		procid.ProcInfo{PID: 3, Exe: "/usr/bin/git", Comm: "git"},
		signature.SignedIdentity{},
		catalog.Identity{ExeBasename: "git", ExePath: "/usr/bin/git", ExeSHA256: strings.Repeat("b", 64)},
	)

	if outcome != outcomeAllow {
		t.Fatal("an upgraded binary must not interrupt work")
	}
	if dec.called {
		t.Fatal("an upgraded binary must not prompt")
	}
	if entry.Reason != "unratified_binary_grace" {
		t.Errorf("Reason = %q, want unratified_binary_grace", entry.Reason)
	}
	if entry.TrustTier == decisionlog.TierCatalogFact {
		t.Error("a grace allow must never be logged as a catalog fact")
	}
	if len(rec.items) != 1 {
		t.Fatalf("queued %d items, want 1", len(rec.items))
	}
	if rec.items[0].NewSHA256 != strings.Repeat("b", 64) {
		t.Errorf("queued the wrong hash: %q", rec.items[0].NewSHA256)
	}
}

func TestDecideBranch_StaleBinaryPromptsWhenPendingWriteFails(t *testing.T) {
	dec := &capturingDecider{}
	d := newDaemonForBranchWithCatalog(t, dec, gitPinCatalog(t, "github.com"))
	d.opts.Pending = failingPending{}

	outcome, entry := d.decideBranchWithIdentity(
		"github.com", nil,
		procid.ProcInfo{PID: 7, Exe: "/usr/bin/git", Comm: "git"},
		signature.SignedIdentity{},
		catalog.Identity{ExeBasename: "git", ExePath: "/usr/bin/git", ExeSHA256: strings.Repeat("b", 64)},
	)

	if outcome == outcomeAllow {
		t.Fatal("stale grace must not allow when the pending review record cannot be written")
	}
	if !dec.called {
		t.Fatal("failed pending write must fall through to the prompt path")
	}
	if entry.Reason == "unratified_binary_grace" {
		t.Fatal("failed pending write must not be logged as grace")
	}
}

func TestDecideBranch_StaleBinaryGetsNoGraceForNewHost(t *testing.T) {
	rec := &recordingPending{}
	d := newDaemonForBranchWithCatalog(t, stubAlwaysDeny{}, gitPinCatalog(t, "github.com"))
	d.opts.Pending = rec

	outcome, entry := d.decideBranchWithIdentity(
		"exfil.example", nil,
		procid.ProcInfo{PID: 4, Exe: "/usr/bin/git", Comm: "git"},
		signature.SignedIdentity{},
		catalog.Identity{ExeBasename: "git", ExePath: "/usr/bin/git", ExeSHA256: strings.Repeat("b", 64)},
	)

	if outcome == outcomeAllow {
		t.Fatal("grace leaked to a host the binary was never ratified for")
	}
	if entry.Reason == "unratified_binary_grace" {
		t.Fatal("a never-ratified host must not take the grace path at all")
	}
	if len(rec.items) != 0 {
		t.Fatal("a new host is a normal unknown, not a pending upgrade")
	}
}

func TestDecideBranch_StaleBinaryNeverHitDeniesWithoutPrompt(t *testing.T) {
	c := &catalog.Catalog{}
	if err := c.Add(catalog.Entry{
		SchemaVersion:        catalog.CurrentSchemaVersion,
		Identity:             catalog.Identity{ExeBasename: "git", ExePath: "/usr/bin/git", ExeSHA256: strings.Repeat("a", 64)},
		ExpectedDestinations: []catalog.Destination{{Host: "github.com", Why: "fixture"}},
		Never:                []string{"evil.example"},
		Explanation:          "git talks to github",
		Evidence:             "fixture",
		Confidence:           catalog.ConfidenceMedium,
		Layer:                "user",
	}); err != nil {
		t.Fatal(err)
	}
	rec := &recordingPending{}
	dec := &capturingDecider{}
	d := newDaemonForBranchWithCatalog(t, dec, c)
	d.opts.Pending = rec

	outcome, entry := d.decideBranchWithIdentity(
		"evil.example", nil,
		procid.ProcInfo{PID: 5, Exe: "/usr/bin/git", Comm: "git"},
		signature.SignedIdentity{},
		catalog.Identity{ExeBasename: "git", ExePath: "/usr/bin/git", ExeSHA256: strings.Repeat("b", 64)},
	)

	if outcome != outcomeDeny {
		t.Fatalf("outcome = %v, want deny", outcome)
	}
	if dec.called {
		t.Fatal("explicit never must not soften into a prompt after a same-path binary change")
	}
	if entry.Reason != "catalog_never_hit" {
		t.Fatalf("Reason = %q, want catalog_never_hit", entry.Reason)
	}
	if len(rec.items) != 0 {
		t.Fatal("a denied never hit must not be queued as a pending allow")
	}
}

func TestDecideBranch_StaleBinaryPromptsAfterDistinctHashCap(t *testing.T) {
	rec := &recordingPending{distinctHashes: maxGraceHashesPerPath}
	dec := &capturingDecider{}
	d := newDaemonForBranchWithCatalog(t, dec, gitPinCatalog(t, "github.com"))
	d.opts.Pending = rec

	outcome, entry := d.decideBranchWithIdentity(
		"github.com", nil,
		procid.ProcInfo{PID: 6, Exe: "/usr/bin/git", Comm: "git"},
		signature.SignedIdentity{},
		catalog.Identity{ExeBasename: "git", ExePath: "/usr/bin/git", ExeSHA256: strings.Repeat("c", 64)},
	)

	if outcome != outcomeDeny {
		t.Fatalf("outcome = %v, want prompt-deny from test decider after grace cap", outcome)
	}
	if !dec.called {
		t.Fatal("high-churn same-path binaries must prompt instead of receiving unbounded grace")
	}
	if entry.Reason == "unratified_binary_grace" {
		t.Fatal("grace must stop once a path has too many distinct pending hashes")
	}
	if len(rec.items) != 0 {
		t.Fatal("over-cap binaries should not be queued through the grace path")
	}
}
