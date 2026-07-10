//go:build darwin

package cli

// StatusReport is the structured, root-free view of egress-guard's launchd +
// routing state. It powers both the CLI status output and the menu-bar glyph.
// It intentionally omits kernel-anchor state, which requires root to read.
type StatusReport struct {
	AgentLoaded      bool
	DaemonPID        int
	BootDaemonLoaded bool
	BootDaemonPID    int
	TUNIface         string
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
	return StatusReport{
		AgentLoaded:      agent.Loaded,
		DaemonPID:        agent.PID,
		BootDaemonLoaded: boot.Loaded,
		BootDaemonPID:    boot.PID,
		TUNIface:         iface,
	}
}
