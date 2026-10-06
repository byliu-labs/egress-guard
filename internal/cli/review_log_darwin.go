//go:build darwin

package cli

import "os"

func reviewLogPath() (string, error) {
	if os.Getenv("XDG_STATE_HOME") == "" && BootDaemonInstalled() {
		return SystemBlockLogPath(), nil
	}
	return BlockLogPath()
}
