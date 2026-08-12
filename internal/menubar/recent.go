//go:build darwin

package menubar

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"

	"github.com/byliu-labs/egress-guard/internal/cli"
	"github.com/byliu-labs/egress-guard/internal/decisionlog"
)

// RecentBlock is one displayable dropped-decision line. Host is the SNI the
// daemon recovered, or "" when the decision carried no identity (e.g. the pf
// original-destination lookup failed). Keeping Host separate from Display means
// callers decide whether an "Allow <host>" action is offerable by inspecting a
// field, not by re-parsing the rendered string.
type RecentBlock struct {
	Display string
	Host    string
}

// logPathResolver returns the decision log the menu should display. It is a var
// so tests can pin it to a temp file. The boot-resident daemon runs as the
// system user (HOME=/var/db/egress-guard under launchd) and writes its log
// there; the menu bar runs as the logged-in user. Reading the user's own
// ~/.local/state copy would surface a stale user-era log while the real
// enforcing daemon's decisions stay invisible — so prefer the system log
// whenever it exists.
var logPathResolver = defaultLogPath

func defaultLogPath() (string, error) {
	if p := cli.SystemBlockLogPath(); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return cli.BlockLogPath()
}

// RecentBlocks returns up to n of the most recent dropped entries, oldest first
// / newest last. A missing log means a fresh install or no decisions yet, so it
// returns an empty result.
func RecentBlocks(n int) ([]RecentBlock, error) {
	if n <= 0 {
		return nil, nil
	}
	path, err := logPathResolver()
	if err != nil {
		return nil, err
	}
	entries, err := decisionlog.ReadFilter(path, decisionlog.Filter{})
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	dropped := entries[:0]
	for _, e := range entries {
		if e.Action == "block" || e.Action == "deny" || e.Decision == decisionlog.DecisionDeny {
			dropped = append(dropped, e)
		}
	}
	if len(dropped) > n {
		dropped = dropped[len(dropped)-n:]
	}
	out := make([]RecentBlock, 0, len(dropped))
	for _, e := range dropped {
		out = append(out, RecentBlock{
			Display: fmt.Sprintf("%s  %s", formatStamp(e.Timestamp), hostLabel(e)),
			Host:    e.Host,
		})
	}
	return out, nil
}

// formatStamp renders the log timestamp as local "YYYY-MM-DD HH:MM". Showing the
// date matters: without it a months-old fossil entry reads as if it happened
// today. Falls back to the raw string if it isn't RFC3339.
func formatStamp(ts string) string {
	if t, err := time.Parse(time.RFC3339, ts); err == nil {
		return t.Local().Format("2006-01-02 15:04")
	}
	return ts
}

// hostLabel is what the row shows after the timestamp: the recovered host, or a
// plain-language explanation of why there is none. "(unknown host)" alone left
// users guessing whether something was wrong on their end.
func hostLabel(e decisionlog.Entry) string {
	if e.Host != "" {
		return e.Host
	}
	switch e.Reason {
	case "":
		return "unknown host"
	case "original_dest_lookup_failed":
		return "unknown host · pf couldn't recover the destination"
	default:
		return "unknown host · " + e.Reason
	}
}
