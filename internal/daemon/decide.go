package daemon

import (
	"net"

	"github.com/byliu-labs/egress-guard/internal/decisionlog"
	"github.com/byliu-labs/egress-guard/internal/procid"
	"github.com/byliu-labs/egress-guard/internal/signature"
)

// finalizeOutcome applies ObserveOnly shadow-mode semantics shared by handle()
// and Decide. In observe mode, every verdict is logged as observe and enforced
// as allow, while Entry.Action retains the original policy verdict.
func (d *Daemon) finalizeOutcome(outcome decisionOutcome, entry decisionlog.Entry) (decisionOutcome, decisionlog.Entry) {
	if d.opts.ObserveOnly {
		entry.Decision = decisionlog.DecisionObserve
		outcome = outcomeAllow
	}
	return outcome, entry
}

func decisionForOutcome(outcome decisionOutcome, entry decisionlog.Entry) decisionlog.Decision {
	if entry.Decision == decisionlog.DecisionObserve {
		return decisionlog.DecisionObserve
	}
	switch outcome {
	case outcomeAllow, outcomeExempt:
		return decisionlog.DecisionAllow
	default:
		return decisionlog.DecisionDeny
	}
}

// Decide runs the same decision engine as handle without the pf/splice I/O
// path. It returns both the authoritative decision and the log entry describing
// it. Callers enforce on the returned Decision, not by re-reading a field from
// the entry.
func (d *Daemon) Decide(host string, dstIP net.IP, pi procid.ProcInfo, sig signature.SignedIdentity) (decisionlog.Decision, decisionlog.Entry) {
	outcome, entry := d.decideBranch(host, dstIP, pi, sig)
	outcome, entry = d.finalizeOutcome(outcome, entry)
	return decisionForOutcome(outcome, entry), entry
}
