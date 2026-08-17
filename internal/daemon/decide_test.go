package daemon

import (
	"net"
	"testing"

	"github.com/byliu-labs/egress-guard/internal/allowlist"
	"github.com/byliu-labs/egress-guard/internal/decisionlog"
	"github.com/byliu-labs/egress-guard/internal/procid"
	"github.com/byliu-labs/egress-guard/internal/signature"
)

func newDaemonForDecide(t *testing.T, observeOnly bool) *Daemon {
	t.Helper()

	d, err := New(Options{
		Listen: "127.0.0.1:0",
		Kernel: &stubKernel{},
		Allow: allowlist.New(allowlist.Config{
			Defaults: allowlist.Layer{Allow: []string{"good.example"}},
		}),
		Log:         &decisionlog.Writer{},
		ObserveOnly: observeOnly,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return d
}

func TestDecide_AllowlistAllow(t *testing.T) {
	d := newDaemonForDecide(t, false)

	_, entry := d.Decide("good.example", net.ParseIP("203.0.113.10"), procid.ProcInfo{}, signature.SignedIdentity{})

	if entry.Decision != decisionlog.DecisionAllow {
		t.Errorf("Decision = %q, want allow", entry.Decision)
	}
}

func TestDecide_UnknownNoPrompt_Denies(t *testing.T) {
	d := newDaemonForDecide(t, false)

	_, entry := d.Decide("unknown.example", net.ParseIP("203.0.113.10"), procid.ProcInfo{}, signature.SignedIdentity{})

	if entry.Decision != decisionlog.DecisionDeny {
		t.Errorf("Decision = %q, want deny", entry.Decision)
	}
	if entry.Reason != "host_unknown_no_prompt" {
		t.Errorf("Reason = %q, want host_unknown_no_prompt", entry.Reason)
	}
}

func TestDecide_ObserveOnly_LogsObserveEnforcesAllow(t *testing.T) {
	d := newDaemonForDecide(t, true)

	dec, entry := d.Decide("unknown.example", net.ParseIP("203.0.113.10"), procid.ProcInfo{}, signature.SignedIdentity{})

	if entry.Decision != decisionlog.DecisionObserve {
		t.Errorf("Decision = %q, want observe", entry.Decision)
	}
	if dec != decisionlog.DecisionObserve {
		t.Errorf("authoritative decision = %q, want observe", dec)
	}
}

func TestFinalizeOutcome_ObserveFlipsToAllow(t *testing.T) {
	d := newDaemonForDecide(t, true)

	outcome, _ := d.finalizeOutcome(outcomeDeny, decisionlog.Entry{Decision: decisionlog.DecisionDeny})

	if outcome != outcomeAllow {
		t.Errorf("outcome = %v, want allow", outcome)
	}
}

func TestDecisionForOutcome_IgnoresDivergentLogField(t *testing.T) {
	cases := []struct {
		name    string
		outcome decisionOutcome
		entry   decisionlog.Entry
		want    decisionlog.Decision
	}{
		{
			name:    "allow outcome wins over stale deny log field",
			outcome: outcomeAllow,
			entry:   decisionlog.Entry{Decision: decisionlog.DecisionDeny},
			want:    decisionlog.DecisionAllow,
		},
		{
			name:    "deny outcome wins over stale allow log field",
			outcome: outcomeDeny,
			entry:   decisionlog.Entry{Decision: decisionlog.DecisionAllow},
			want:    decisionlog.DecisionDeny,
		},
		{
			name:    "exempt outcome authorizes like the pf fast path",
			outcome: outcomeExempt,
			entry:   decisionlog.Entry{Decision: decisionlog.DecisionDeny},
			want:    decisionlog.DecisionAllow,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := decisionForOutcome(tc.outcome, tc.entry); got != tc.want {
				t.Fatalf("decisionForOutcome(%v, entry decision %q) = %q, want %q",
					tc.outcome, tc.entry.Decision, got, tc.want)
			}
		})
	}
}
