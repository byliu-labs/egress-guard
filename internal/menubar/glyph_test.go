//go:build darwin

package menubar

import (
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
