//go:build darwin

package menubar

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const menubarAgentLabel = "com.byliu.egress-guard.menubar"

const loginPlistTmpl = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>%s</string>
  <key>ProgramArguments</key>
  <array>
%s
  </array>
  <key>RunAtLoad</key><true/>
</dict>
</plist>
`

func loginAgentPlist(programArgs []string) string {
	var b strings.Builder
	for _, a := range programArgs {
		fmt.Fprintf(&b, "    <string>%s</string>\n", a)
	}
	return fmt.Sprintf(loginPlistTmpl, menubarAgentLabel, strings.TrimRight(b.String(), "\n"))
}

func plistPath(plistDir string) string {
	base := plistDir
	if base == "" {
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, "Library", "LaunchAgents")
	}
	return filepath.Join(base, menubarAgentLabel+".plist")
}

func installLoginAgentFile(plistDir string, programArgs []string) (string, error) {
	path := plistPath(plistDir)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(loginAgentPlist(programArgs)), 0o644); err != nil {
		return "", err
	}
	return path, nil
}

func removeLoginAgentFile(plistDir string) error {
	err := os.Remove(plistPath(plistDir))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func LoginAgentInstalled(plistDir string) bool {
	_, err := os.Stat(plistPath(plistDir))
	return err == nil
}

// InstallLoginAgent writes the plist and bootstraps it with launchctl.
func InstallLoginAgent(plistDir string) (string, error) {
	path, err := installLoginAgentFile(plistDir, []string{installedBarPath})
	if err != nil {
		return "", err
	}
	_ = exec.Command("launchctl", "load", path).Run()
	return path, nil
}

// RemoveLoginAgent unloads and deletes the plist.
func RemoveLoginAgent(plistDir string) error {
	path := plistPath(plistDir)
	_ = exec.Command("launchctl", "unload", path).Run()
	return removeLoginAgentFile(plistDir)
}
