package daemon

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

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

func TestDecideBranch_NameOnlyBaselineDoesNotAllowWithoutPrompt(t *testing.T) {
	cat := &catalog.Catalog{}
	pi := procid.ProcInfo{PID: 13, Exe: "/tmp/git", Comm: "git"}
	sig := signature.SignedIdentity{}
	if err := cat.Add(catalog.Entry{
		SchemaVersion:        catalog.CurrentSchemaVersion,
		Identity:             catalog.Identity{ExeBasename: "git"},
		ExpectedDestinations: []catalog.Destination{{Host: "github.com", Why: "test fixture"}},
		Explanation:          "git talks to GitHub",
		Evidence:             "basename-only public catalog fixture",
		Confidence:           catalog.ConfidenceMedium,
		Layer:                "baseline",
	}); err != nil {
		t.Fatalf("cat.Add: %v", err)
	}

	dec := &capturingDecider{}
	d := newDaemonForBranchWithCatalog(t, dec, cat)
	outcome, entry := d.decideBranch("github.com", nil, pi, sig)
	if outcome != outcomeDeny {
		t.Errorf("outcome = %v, want deny", outcome)
	}
	if entry.Reason != "user_denied_or_timeout" {
		t.Errorf("entry.Reason = %q, want user_denied_or_timeout", entry.Reason)
	}
	if !dec.called {
		t.Fatal("prompt was not shown for non-authoritative catalog match")
	}
	if !dec.got.CatalogMatch.Found {
		t.Fatal("prompt did not receive the baseline explanation")
	}
	if dec.got.CatalogMatch.Authoritative {
		t.Fatal("basename-only baseline entry must not be authoritative")
	}
	if entry.TrustTier != decisionlog.TierPrompt {
		t.Errorf("entry.TrustTier = %q, want prompt", entry.TrustTier)
	}
}

func TestDecideBranch_ExeSHA256BaselineAllowsMatchingBinary(t *testing.T) {
	cat := &catalog.Catalog{}
	dir := t.TempDir()
	exePath := filepath.Join(dir, "git")
	exeBytes := []byte("real git fixture")
	if err := os.WriteFile(exePath, exeBytes, 0o755); err != nil {
		t.Fatalf("write executable fixture: %v", err)
	}
	realPath, err := filepath.EvalSymlinks(exePath)
	if err != nil {
		t.Fatalf("resolve executable fixture: %v", err)
	}
	sum := sha256.Sum256(exeBytes)
	pi := procid.ProcInfo{PID: 14, Exe: exePath, Comm: "git"}
	if err := cat.Add(catalog.Entry{
		SchemaVersion:        catalog.CurrentSchemaVersion,
		Identity:             catalog.Identity{ExeBasename: "git", ExePath: realPath, ExeSHA256: hex.EncodeToString(sum[:])},
		ExpectedDestinations: []catalog.Destination{{Host: "github.com", Why: "test fixture"}},
		Explanation:          "this pinned git binary talks to GitHub",
		Evidence:             "test fixture sha256",
		Confidence:           catalog.ConfidenceMedium,
		Layer:                "baseline",
	}); err != nil {
		t.Fatalf("cat.Add: %v", err)
	}

	d := newDaemonForBranchWithCatalog(t, nil, cat)
	outcome, entry := d.decideBranch("github.com", nil, pi, signature.SignedIdentity{})
	if outcome != outcomeAllow {
		t.Errorf("outcome = %v, want allow", outcome)
	}
	if entry.Reason != "catalog_fact" {
		t.Errorf("entry.Reason = %q, want catalog_fact", entry.Reason)
	}
	if entry.ExeSHA256 != hex.EncodeToString(sum[:]) {
		t.Errorf("entry.ExeSHA256 = %q, want fixture hash", entry.ExeSHA256)
	}
}

func TestDecideBranch_SameInodeRewriteDoesNotUseStaleHashForCatalogFact(t *testing.T) {
	cat := &catalog.Catalog{}
	dir := t.TempDir()
	exePath := filepath.Join(dir, "pinnedtool")
	exeBytes := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err := os.WriteFile(exePath, exeBytes, 0o755); err != nil {
		t.Fatalf("write executable fixture: %v", err)
	}
	realPath, err := filepath.EvalSymlinks(exePath)
	if err != nil {
		t.Fatalf("resolve executable fixture: %v", err)
	}
	sum := sha256.Sum256(exeBytes)
	if err := cat.Add(catalog.Entry{
		SchemaVersion:        catalog.CurrentSchemaVersion,
		Identity:             catalog.Identity{ExeBasename: "pinnedtool", ExePath: realPath, ExeSHA256: hex.EncodeToString(sum[:])},
		ExpectedDestinations: []catalog.Destination{{Host: "pypi.org", Why: "test fixture"}},
		Explanation:          "this pinned tool talks to PyPI",
		Evidence:             "test fixture sha256",
		Confidence:           catalog.ConfidenceMedium,
		Layer:                "user",
	}); err != nil {
		t.Fatalf("cat.Add: %v", err)
	}
	fi, err := os.Stat(exePath)
	if err != nil {
		t.Fatal(err)
	}
	mtime := fi.ModTime()

	d := newDaemonForBranchWithCatalog(t, nil, cat)
	pi := procid.ProcInfo{PID: 15, Exe: exePath, Comm: "pinnedtool"}
	if outcome, entry := d.decideBranch("pypi.org", nil, pi, signature.SignedIdentity{}); outcome != outcomeAllow || entry.Reason != "catalog_fact" {
		t.Fatalf("first decision: outcome=%v entry=%+v, want catalog_fact allow", outcome, entry)
	}

	time.Sleep(20 * time.Millisecond)
	f, err := os.OpenFile(exePath, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"), 0); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(exePath, mtime, mtime); err != nil {
		t.Fatal(err)
	}

	rec := &recordingPending{}
	d.opts.Pending = rec
	outcome, entry := d.decideBranch("pypi.org", nil, pi, signature.SignedIdentity{})
	if outcome == outcomeAllow && entry.TrustTier == decisionlog.TierCatalogFact {
		t.Fatalf("same-inode rewrite was allowed as stale catalog fact: %+v", entry)
	}
	if len(rec.items) != 1 {
		t.Fatalf("pending items = %d, want changed binary queued for review", len(rec.items))
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
