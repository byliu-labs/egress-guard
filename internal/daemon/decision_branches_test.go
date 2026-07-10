package daemon

import (
	"testing"

	"github.com/byliu-labs/egress-guard/internal/allowlist"
	"github.com/byliu-labs/egress-guard/internal/decisionlog"
	"github.com/byliu-labs/egress-guard/internal/exempt"
	"github.com/byliu-labs/egress-guard/internal/procid"
	"github.com/byliu-labs/egress-guard/internal/prompt"
	"github.com/byliu-labs/egress-guard/internal/signature"
)

// newDaemonForBranch constructs a daemon suitable for direct decideBranch()
// calls. No listener is started — decideBranch is pure with respect to I/O.
func newDaemonForBranch(t *testing.T, dec prompt.Decider, ex *exempt.Catalog) *Daemon {
	t.Helper()
	bl := &decisionlog.Writer{} // Branch tests don't write; stub Writer is fine.
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
		Log:       bl,
		ProcID:    procid.NewStub(),
		Signature: signature.NewStub(),
		Exempt:    ex,
		Prompt:    dec,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return d
}

func TestDecideBranch_ExemptShortCircuits(t *testing.T) {
	exempted, err := exempt.LoadFromString(`
[[macos]]
exe_basename = "Safari"
team_id      = "APPLE"
`)
	if err != nil {
		t.Fatalf("LoadFromString: %v", err)
	}
	d := newDaemonForBranch(t, stubAlwaysDeny{}, exempted)
	pi := procid.ProcInfo{
		PID:  5,
		Exe:  "/Applications/Safari.app/Contents/MacOS/Safari",
		Comm: "Safari",
	}
	sig := signature.SignedIdentity{Valid: true, TeamID: "APPLE"}
	outcome, entry := d.decideBranch("randomsite.example", nil, pi, sig)
	if outcome != outcomeExempt {
		t.Errorf("outcome = %v, want exempt", outcome)
	}
	if entry.Action != "allow" || entry.Reason != "exempt_app" {
		t.Errorf("entry = %+v, want allow/exempt_app", entry)
	}
	if entry.PID != 5 {
		t.Errorf("entry.PID = %d, want 5 (proc context must be populated)", entry.PID)
	}
	if entry.TeamID != "APPLE" || !entry.SigValid {
		t.Errorf("entry TeamID=%q SigValid=%v, want APPLE/true", entry.TeamID, entry.SigValid)
	}
	if entry.TrustTier != "" {
		t.Errorf("entry.TrustTier = %q, want empty", entry.TrustTier)
	}
}

func TestDecideBranch_AllowedHostBypassesPrompt(t *testing.T) {
	defaults, _ := exempt.LoadDefault()
	// Prompt is "always deny" — so if the allowlist were ignored, this would
	// fall through to deny. Allow must short-circuit.
	d := newDaemonForBranch(t, stubAlwaysDeny{}, defaults)
	pi := procid.ProcInfo{PID: 6, Exe: "/usr/bin/curl", Comm: "curl"}
	sig := signature.SignedIdentity{Valid: true, TeamID: "APPLE"} // signed but on always-filtered list
	outcome, entry := d.decideBranch("allow.example", nil, pi, sig)
	if outcome != outcomeAllow {
		t.Errorf("outcome = %v, want allow", outcome)
	}
	if entry.PID != 6 {
		t.Errorf("entry.PID = %d, want 6", entry.PID)
	}
	if entry.TrustTier != decisionlog.TierDefault {
		t.Errorf("entry.TrustTier = %q, want TierDefault", entry.TrustTier)
	}
}

func TestDecideBranch_UnknownHostGoesToPrompt(t *testing.T) {
	defaults, _ := exempt.LoadDefault()
	d := newDaemonForBranch(t, stubAlwaysAllow{}, defaults)
	pi := procid.ProcInfo{PID: 7, Exe: "/usr/bin/curl", Comm: "curl"}
	sig := signature.SignedIdentity{Valid: true, TeamID: "APPLE"}
	outcome, entry := d.decideBranch("nowhere.example", nil, pi, sig)
	if outcome != outcomeAllow {
		t.Errorf("outcome = %v, want allow (via prompt)", outcome)
	}
	if entry.Reason != "user_allowed" {
		t.Errorf("entry.Reason = %q, want user_allowed", entry.Reason)
	}
	if entry.TrustTier != decisionlog.TierPrompt {
		t.Errorf("entry.TrustTier = %q, want TierPrompt", entry.TrustTier)
	}
}

func TestDecideBranch_PromptNilDeniesUnknown(t *testing.T) {
	defaults, _ := exempt.LoadDefault()
	d := newDaemonForBranch(t, nil, defaults)
	pi := procid.ProcInfo{PID: 8, Exe: "/usr/bin/curl"}
	sig := signature.SignedIdentity{Valid: true, TeamID: "APPLE"}
	outcome, entry := d.decideBranch("nowhere.example", nil, pi, sig)
	if outcome != outcomeDeny {
		t.Errorf("outcome = %v, want deny", outcome)
	}
	if entry.Reason != "host_unknown_no_prompt" {
		t.Errorf("entry.Reason = %q, want host_unknown_no_prompt", entry.Reason)
	}
	if entry.TrustTier != decisionlog.TierDefault {
		t.Errorf("entry.TrustTier = %q, want TierDefault", entry.TrustTier)
	}
}

func TestDecideBranch_DenylistedHostDeniesWithoutPrompt(t *testing.T) {
	defaults, _ := exempt.LoadDefault()
	d := newDaemonForBranch(t, stubAlwaysAllow{}, defaults)
	pi := procid.ProcInfo{PID: 9, Exe: "/usr/bin/curl"}
	sig := signature.SignedIdentity{Valid: true, TeamID: "APPLE"}
	outcome, entry := d.decideBranch("deny.example", nil, pi, sig)
	if outcome != outcomeDeny {
		t.Errorf("outcome = %v, want deny", outcome)
	}
	if entry.Reason != "host_denylisted" {
		t.Errorf("entry.Reason = %q, want host_denylisted", entry.Reason)
	}
	if entry.TrustTier != decisionlog.TierDefault {
		t.Errorf("entry.TrustTier = %q, want TierDefault", entry.TrustTier)
	}
}
