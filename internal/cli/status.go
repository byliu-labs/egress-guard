package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func logFootprint(logPath string) (int, int64, error) {
	var total int64
	if fi, err := os.Stat(logPath); err == nil {
		total += fi.Size()
	} else if !os.IsNotExist(err) {
		return 0, 0, err
	}

	matches, err := filepath.Glob(logPath + ".*")
	if err != nil {
		return 0, 0, err
	}
	segments := 0
	for _, m := range matches {
		if strings.HasSuffix(m, ".tmp") {
			continue
		}
		fi, err := os.Stat(m)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return 0, 0, err
		}
		segments++
		total += fi.Size()
	}
	return segments, total, nil
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
