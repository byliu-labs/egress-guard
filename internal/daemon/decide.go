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

// Decide runs the same decision engine as handle without the pf/splice I/O
// path. The caller enforces deny as drop and allow or observe as allow.
func (d *Daemon) Decide(host string, dstIP net.IP, pi procid.ProcInfo, sig signature.SignedIdentity) decisionlog.Entry {
	outcome, entry := d.decideBranch(host, dstIP, pi, sig)
	_, entry = d.finalizeOutcome(outcome, entry)
	return entry
}
