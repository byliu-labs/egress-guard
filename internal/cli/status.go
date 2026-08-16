package cli

import (
	"fmt"
	"io"

	"github.com/byliu-labs/egress-guard/internal/decisionlog"
)

func logFootprint(logPath string) (int, int64, error) {
	return decisionlog.Footprint(logPath)
}

func printLogFootprint(w io.Writer) {
	logPath, err := BlockLogPath()
	if err != nil {
		return
	}
	segs, bytes, err := logFootprint(logPath)
	if err != nil {
		return
	}
	fmt.Fprintf(w, "decision log:  %.1f MiB across %d rotated segment(s) + live file\n",
		float64(bytes)/(1<<20), segs)
}
