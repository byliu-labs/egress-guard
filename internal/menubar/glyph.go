//go:build darwin

package menubar

import (
	"fmt"

	"github.com/byliu-labs/egress-guard/internal/cli"
)

// Glyph maps status to a menu-bar emoji and tooltip. A TUN-mode proxy owning
// the default route silently disables enforcement, so it outranks every other
// signal: the icon must warn even when the daemon looks healthy.
func Glyph(r cli.StatusReport) (title, tooltip string) {
	protected := (r.BootDaemonLoaded && r.BootDaemonPID > 0) || (r.AgentLoaded && r.DaemonPID > 0)
	switch {
	case r.TUNIface != "":
		return "⚠️", fmt.Sprintf("Bypassed: %s owns the default route; egress-guard enforces nothing", r.TUNIface)
	case protected:
		if r.PendingReviews > 0 {
			return fmt.Sprintf("🛡️%d", r.PendingReviews),
				fmt.Sprintf("Protected: daemon running; %d updated binaries awaiting review", r.PendingReviews)
		}
		return "🛡️", "Protected: daemon running"
	// Both boot-daemon fault states rank BELOW protected: checkDaemonJob and
	// checkAgent are independent probes, so a launchd query that fails (or a
	// deliberately disabled boot daemon) says nothing about a LaunchAgent that
	// is enforcing right now. Ranking them higher hides the shield — and the
	// pending-review badge — on a machine that is genuinely protected.
	case r.BootDaemonDisabled:
		return "⚠️", "Disabled: run `sudo launchctl enable system/com.byliu.egress-guard.daemon`"
	case r.BootDaemonUnknown:
		return "⚠️", "Status unavailable: could not query launchd"
	case r.BootDaemonLoaded || r.AgentLoaded:
		return "⚠️", "Daemon restarting"
	default:
		return "⛔", "Not protected: click to install"
	}
}

// StatusLine is the one-liner shown as the always-visible top menu item. macOS
// menu-bar tooltips are unreliable, so the icon's meaning must be readable in
// the menu itself without hovering.
func StatusLine(r cli.StatusReport) string {
	title, tip := Glyph(r)
	return title + "  " + tip
}
