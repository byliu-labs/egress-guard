//go:build darwin

package menubar

import (
	"strings"
	"testing"

	"github.com/byliu-labs/egress-guard/internal/cli"
)

func TestGlyph(t *testing.T) {
	cases := []struct {
		name      string
		r         cli.StatusReport
		wantTitle string
		wantTip   string
	}{
		{"protected", cli.StatusReport{BootDaemonLoaded: true, BootDaemonPID: 42}, "🛡️", ""},
		{"supported-user-agent", cli.StatusReport{AgentLoaded: true, DaemonPID: 42}, "🛡️", ""},
		{"tun-bypass-wins", cli.StatusReport{AgentLoaded: true, DaemonPID: 42, TUNIface: "utun4"}, "⚠️", "utun4"},
		{"tun-bypass-wins-over-unknown", cli.StatusReport{BootDaemonUnknown: true, TUNIface: "utun4"}, "⚠️", "utun4"},
		{"daemon-restarting", cli.StatusReport{BootDaemonLoaded: true, BootDaemonPID: 0}, "⚠️", ""},
		{"user-agent-restarting", cli.StatusReport{AgentLoaded: true}, "⚠️", ""},
		{"boot-daemon-disabled", cli.StatusReport{BootDaemonDisabled: true}, "⚠️", "launchctl enable"},
		{"boot-daemon-unknown", cli.StatusReport{BootDaemonUnknown: true}, "⚠️", "Status unavailable"},
		{"protected-wins-over-disabled", cli.StatusReport{AgentLoaded: true, DaemonPID: 42, BootDaemonDisabled: true}, "🛡️", "Protected"},
		{"protected-wins-over-unknown", cli.StatusReport{AgentLoaded: true, DaemonPID: 42, BootDaemonUnknown: true}, "🛡️", "Protected"},
		{"pending-badge-survives-unknown", cli.StatusReport{AgentLoaded: true, DaemonPID: 42, PendingReviews: 3, BootDaemonUnknown: true}, "🛡️3", "3 updated binaries"},
		// Both fault states also outrank "Daemon restarting", and that choice
		// needs a row or the next refactor flips it for free. On the agent path
		// with DaemonPID == 0 nothing is enforcing under either message, so the
		// tooltip should carry the durable condition the user can act on rather
		// than a guess that a restart is in progress and will resolve itself.
		{"disabled-outranks-restarting", cli.StatusReport{AgentLoaded: true, BootDaemonDisabled: true}, "⚠️", "launchctl enable"},
		{"unknown-outranks-restarting", cli.StatusReport{AgentLoaded: true, BootDaemonUnknown: true}, "⚠️", "Status unavailable"},
		// The badge boundary. Every other row uses 3 or 0, so `PendingReviews > 0`
		// could become `> 1` unnoticed — and one queued binary is the modal case,
		// since the count is 1 the moment the first upgraded binary is graced.
		{"pending-badge-at-one", cli.StatusReport{AgentLoaded: true, DaemonPID: 42, PendingReviews: 1}, "🛡️1", "1 updated binaries"},
		// Both conjuncts of `protected` carry weight. A PID without its loaded
		// flag must not show the shield: this is the one surface that tells a
		// user they are protected, so it does not get to infer that from half a
		// signal, even where the probe makes the state unlikely.
		{"agent-pid-without-agent-loaded", cli.StatusReport{DaemonPID: 42}, "⛔", ""},
		{"boot-pid-without-boot-loaded", cli.StatusReport{BootDaemonPID: 42}, "⛔", ""},
		{"not-protected", cli.StatusReport{}, "⛔", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			title, tip := Glyph(c.r)
			if title != c.wantTitle {
				t.Errorf("title = %q, want %q", title, c.wantTitle)
			}
			if tip == "" {
				t.Errorf("tooltip must not be empty")
			}
			if c.wantTip != "" && !strings.Contains(tip, c.wantTip) {
				t.Errorf("tooltip = %q, want it to contain %q", tip, c.wantTip)
			}
		})
	}
}

func TestGlyph_ShowsPendingCount(t *testing.T) {
	title, tip := Glyph(cli.StatusReport{BootDaemonLoaded: true, BootDaemonPID: 42, PendingReviews: 3})
	if !strings.Contains(title, "3") {
		t.Errorf("title = %q, want the pending count in it", title)
	}
	if !strings.Contains(tip, "3") {
		t.Errorf("tooltip = %q, want the pending count in it", tip)
	}
}

func TestGlyph_BypassWarningOutranksPendingCount(t *testing.T) {
	title, tip := Glyph(cli.StatusReport{TUNIface: "utun4", BootDaemonLoaded: true, BootDaemonPID: 42, PendingReviews: 3})
	if title != "⚠️" {
		t.Errorf("title = %q, want the bypass warning to win", title)
	}
	if !strings.Contains(tip, "utun4") {
		t.Errorf("tooltip = %q, want the bypass reason", tip)
	}
}

func TestGlyph_NoBadgeWhenQueueEmpty(t *testing.T) {
	title, _ := Glyph(cli.StatusReport{BootDaemonLoaded: true, BootDaemonPID: 42})
	if title != "🛡️" {
		t.Errorf("title = %q, want the plain protected glyph", title)
	}
}
