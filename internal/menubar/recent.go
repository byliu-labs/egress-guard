//go:build darwin

package menubar

import (
	"errors"
	"fmt"
	"io/fs"
	"time"

	"github.com/byliu-labs/egress-guard/internal/cli"
	"github.com/byliu-labs/egress-guard/internal/decisionlog"
)

// RecentBlocks returns up to n of the most recent dropped entries as display
// strings ("HH:MM host"), oldest first / newest last. A missing log means a
// fresh install or no decisions yet, so it returns an empty result.
func RecentBlocks(n int) ([]string, error) {
	if n <= 0 {
		return nil, nil
	}
	path, err := cli.BlockLogPath()
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
	out := make([]string, 0, len(dropped))
	for _, e := range dropped {
		hhmm := e.Timestamp
		if ts, perr := time.Parse(time.RFC3339, e.Timestamp); perr == nil {
			hhmm = ts.Local().Format("15:04")
		}
		host := e.Host
		if host == "" {
			host = "(unknown host)"
		}
		out = append(out, fmt.Sprintf("%s  %s", hhmm, host))
	}
	return out, nil
}
