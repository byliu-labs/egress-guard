//go:build darwin

package kernel

import (
	"fmt"
	"os"
	"strings"
)

const pfConfPath = "/etc/pf.conf"
const rdrAnchorLine = `rdr-anchor "egress-guard"`
const filterAnchorLine = `anchor "egress-guard"`

var readPfConf = func() (string, error) {
	data, err := os.ReadFile(pfConfPath)
	return string(data), err
}

// AnchorDeclared is an unprivileged hint about the file on disk. The loaded
// ruleset can differ, so true alone never proves protection is installed.
func AnchorDeclared() (bool, error) {
	text, err := readPfConf()
	if err != nil {
		return false, fmt.Errorf("kernel: read %s: %w", pfConfPath, err)
	}
	rdr, filter := pfConfState(text)
	return rdr && filter, nil
}

func pfConfState(text string) (hasRdr, hasFilter bool) {
	for _, line := range strings.Split(text, "\n") {
		switch strings.TrimSpace(line) {
		case rdrAnchorLine:
			hasRdr = true
		case filterAnchorLine:
			hasFilter = true
		}
	}
	return hasRdr, hasFilter
}

func insertAnchors(text string) (string, error) {
	rdr, filter := pfConfState(text)
	var err error
	if !rdr {
		text, err = insertAfter(text, `rdr-anchor "com.apple/*"`, rdrAnchorLine)
		if err != nil {
			return "", err
		}
	}
	if !filter {
		text, err = insertAfter(text, `anchor "com.apple/*"`, filterAnchorLine)
		if err != nil {
			return "", err
		}
	}
	return text, nil
}

func insertAfter(text, marker, add string) (string, error) {
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		if strings.TrimSpace(line) == marker {
			out := make([]string, 0, len(lines)+1)
			out = append(out, lines[:i+1]...)
			out = append(out, add)
			out = append(out, lines[i+1:]...)
			return strings.Join(out, "\n"), nil
		}
	}
	return "", fmt.Errorf("kernel: anchor marker %q not found", marker)
}

func removeAnchors(text string) string {
	lines := strings.Split(text, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		if trimmed := strings.TrimSpace(line); trimmed != rdrAnchorLine && trimmed != filterAnchorLine {
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n")
}
