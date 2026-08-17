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
	}{
		{"protected", cli.StatusReport{AgentLoaded: true, DaemonPID: 42}, "🛡️"},
		{"tun-bypass-wins", cli.StatusReport{AgentLoaded: true, DaemonPID: 42, TUNIface: "utun4"}, "⚠️"},
		{"daemon-restarting", cli.StatusReport{AgentLoaded: true, DaemonPID: 0}, "⚠️"},
		{"not-protected", cli.StatusReport{}, "⛔"},
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
		})
	}
}

func TestGlyph_ShowsPendingCount(t *testing.T) {
	title, tip := Glyph(cli.StatusReport{AgentLoaded: true, DaemonPID: 42, PendingReviews: 3})
	if !strings.Contains(title, "3") {
		t.Errorf("title = %q, want the pending count in it", title)
	}
	if !strings.Contains(tip, "3") {
		t.Errorf("tooltip = %q, want the pending count in it", tip)
	}
}

func TestGlyph_BypassWarningOutranksPendingCount(t *testing.T) {
	title, tip := Glyph(cli.StatusReport{TUNIface: "utun4", AgentLoaded: true, DaemonPID: 42, PendingReviews: 3})
	if title != "⚠️" {
		t.Errorf("title = %q, want the bypass warning to win", title)
	}
	if !strings.Contains(tip, "utun4") {
		t.Errorf("tooltip = %q, want the bypass reason", tip)
	}
}

func TestGlyph_NoBadgeWhenQueueEmpty(t *testing.T) {
	title, _ := Glyph(cli.StatusReport{AgentLoaded: true, DaemonPID: 42})
	if title != "🛡️" {
		t.Errorf("title = %q, want the plain protected glyph", title)
	}
}
