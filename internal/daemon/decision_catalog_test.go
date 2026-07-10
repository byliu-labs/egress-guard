package daemon

import (
	"testing"

	"github.com/byliu-labs/egress-guard/internal/allowlist"
	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/decisionlog"
	"github.com/byliu-labs/egress-guard/internal/procid"
	"github.com/byliu-labs/egress-guard/internal/prompt"
	"github.com/byliu-labs/egress-guard/internal/signature"
)

func newDaemonForBranchWithCatalog(t *testing.T, dec prompt.Decider, cat *catalog.Catalog) *Daemon {
	t.Helper()
	a := allowlist.New(allowlist.Config{
		Defaults: allowlist.Layer{
			Allow: []string{"allow.example"},
			Deny:  []string{"deny.example"},
		},
	})
	d, err := New(Options{
		Listen:    "127.0.0.1:0",
		Kernel:    &stubKernel{},
		Allow:     a,
		Log:       &decisionlog.Writer{},
		ProcID:    procid.NewStub(),
		Signature: signature.NewStub(),
		Prompt:    dec,
		Catalog:   cat,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return d
}

func TestDecideBranch_CatalogNeverHitDeniesWithoutPrompt(t *testing.T) {
	cat := &catalog.Catalog{}
	pi := procid.ProcInfo{PID: 10, Exe: "/usr/bin/badapp", Comm: "badapp"}
	sig := signature.SignedIdentity{Valid: true, TeamID: "TEAMX"}
	if err := cat.Add(catalog.Entry{
		SchemaVersion: catalog.CurrentSchemaVersion,
		Identity:      catalog.Identity{ExeBasename: "badapp", TeamID: "TEAMX"},
		Never:         []string{"bad.example"},
		Explanation:   "badapp must never reach bad.example",
		Evidence:      "test fixture",
		Confidence:    catalog.ConfidenceHigh,
		Layer:         "user",
	}); err != nil {
		t.Fatalf("cat.Add: %v", err)
	}

	d := newDaemonForBranchWithCatalog(t, stubAlwaysAllow{}, cat)
	outcome, entry := d.decideBranch("bad.example", nil, pi, sig)
	if outcome != outcomeDeny {
		t.Errorf("outcome = %v, want deny", outcome)
	}
	if entry.Reason != "catalog_never_hit" {
		t.Errorf("entry.Reason = %q, want catalog_never_hit", entry.Reason)
	}
	if entry.TrustTier != decisionlog.TierCatalogFact {
		t.Errorf("entry.TrustTier = %q, want catalog fact", entry.TrustTier)
	}
}

func TestDecideBranch_CatalogFoundAllowsWithoutPrompt(t *testing.T) {
	cat := &catalog.Catalog{}
	pi := procid.ProcInfo{PID: 11, Exe: "/usr/bin/driftapp", Comm: "driftapp"}
	sig := signature.SignedIdentity{Valid: true, TeamID: "TEAMX"}
	if err := cat.Add(catalog.Entry{
		SchemaVersion:        catalog.CurrentSchemaVersion,
		Identity:             catalog.Identity{ExeBasename: "driftapp", TeamID: "TEAMX"},
		ExpectedDestinations: []catalog.Destination{{Host: "driftapp.io", Why: "test fixture"}},
		Explanation:          "driftapp talks to driftapp.io",
		Evidence:             "test fixture",
		Confidence:           catalog.ConfidenceHigh,
		Layer:                "user",
	}); err != nil {
		t.Fatalf("cat.Add: %v", err)
	}

	d := newDaemonForBranchWithCatalog(t, stubAlwaysDeny{}, cat)
	outcome, entry := d.decideBranch("driftapp.io", nil, pi, sig)
	if outcome != outcomeAllow {
		t.Errorf("outcome = %v, want allow", outcome)
	}
	if entry.Reason != "catalog_fact" {
		t.Errorf("entry.Reason = %q, want catalog_fact", entry.Reason)
	}
	if entry.TrustTier != decisionlog.TierCatalogFact {
		t.Errorf("entry.TrustTier = %q, want catalog fact", entry.TrustTier)
	}
}

func TestDecideBranch_NoCatalogMatchStillPromptsNeverAutoAllows(t *testing.T) {
	cat := &catalog.Catalog{}
	pi := procid.ProcInfo{PID: 12, Exe: "/usr/bin/newapp", Comm: "newapp"}
	sig := signature.SignedIdentity{Valid: true, TeamID: "TEAMX"}

	d := newDaemonForBranchWithCatalog(t, stubAlwaysDeny{}, cat)
	outcome, entry := d.decideBranch("nowhere.example", nil, pi, sig)
	if outcome != outcomeDeny {
		t.Errorf("outcome = %v, want deny", outcome)
	}
	if entry.Reason != "user_denied_or_timeout" {
		t.Errorf("entry.Reason = %q, want user_denied_or_timeout", entry.Reason)
	}
}
