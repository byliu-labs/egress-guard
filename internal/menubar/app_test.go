//go:build darwin

package menubar

import (
	"strings"
	"testing"

	"github.com/byliu-labs/egress-guard/internal/cli"
)

// StatusLine backs the always-visible top menu row (macOS tooltips are
// unreliable), so it must render a non-empty explanation and, for a TUN bypass,
// name the interface that is overriding enforcement.
func TestStatusLine(t *testing.T) {
	if s := StatusLine(cli.StatusReport{AgentLoaded: true, DaemonPID: 42}); s == "" {
		t.Error("StatusLine must not be empty for a protected daemon")
	}
	bypass := StatusLine(cli.StatusReport{AgentLoaded: true, DaemonPID: 42, TUNIface: "utun17"})
	if !strings.Contains(bypass, "utun17") {
		t.Errorf("TUN-bypass status = %q, want it to name utun17", bypass)
	}
}
