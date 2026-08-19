//go:build darwin

package cli

import "github.com/byliu-labs/egress-guard/internal/pending"

// StatusReport is the structured, root-free view of egress-guard's launchd +
// routing state. It powers both the CLI status output and the menu-bar glyph.
// It intentionally omits kernel-anchor state, which requires root to read.
type StatusReport struct {
	AgentLoaded        bool
	DaemonPID          int
	BootDaemonLoaded   bool
	BootDaemonPID      int
	BootDaemonDisabled bool
	BootDaemonUnknown  bool
	TUNIface           string
	PendingReviews     int
}

// Probe gathers launchd + default-route state. It shells out only to
// user-runnable commands (launchctl, route), so it never needs sudo.
func Probe() StatusReport {
	agent := checkAgent()
	boot := checkDaemonJob()
	iface := defaultRouteInterface()
	if !isTUNInterface(iface) {
		iface = ""
	}
	pendingReviews := 0
	if p, err := configPath("pending-reviews.jsonl"); err == nil {
		if n, err := pending.Count(p); err == nil {
			pendingReviews = n
		}
	}
	return StatusReport{
		AgentLoaded:        agent.Loaded,
		DaemonPID:          agent.PID,
		BootDaemonLoaded:   boot.Loaded,
		BootDaemonPID:      boot.PID,
		BootDaemonDisabled: boot.Disabled,
		BootDaemonUnknown:  boot.Unknown,
		TUNIface:           iface,
		PendingReviews:     pendingReviews,
	}
}
