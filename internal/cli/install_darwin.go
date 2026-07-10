//go:build darwin

package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const launchdTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.byliu.egress-guard</string>
    <key>ProgramArguments</key>
    <array>
        <string>{{BINARY}}</string>
        <string>start</string>
        <string>--port={{PORT}}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>EnvironmentVariables</key>
    <dict>
        <key>HOME</key>
        <string>{{HOME}}</string>
        <key>PATH</key>
        <string>/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin</string>
    </dict>
    <key>StandardOutPath</key>
    <string>{{STATE}}/daemon.log</string>
    <key>StandardErrorPath</key>
    <string>{{STATE}}/daemon.err</string>
</dict>
</plist>
`

// renderLaunchdPlist substitutes the template placeholders. Extracted from
// installLaunchAgent so unit tests can verify the rendered XML without
// touching the filesystem or invoking launchctl.
func renderLaunchdPlist(binPath string, port int, state string, home string) string {
	return strings.NewReplacer(
		"{{BINARY}}", binPath,
		"{{PORT}}", fmt.Sprintf("%d", port),
		"{{STATE}}", state,
		"{{HOME}}", home,
	).Replace(launchdTemplate)
}

// installLaunchAgent writes the plist for the calling user and loads it via
// launchctl. Idempotent: re-running unloads first, then loads. The caller
// (cli.Enable) refuses to run as root, so resolveHome here always resolves
// to the actual user's home — never /var/root.
func installLaunchAgent(port int) error {
	binPath, err := os.Executable()
	if err != nil {
		return err
	}
	if resolved, err := filepath.EvalSymlinks(binPath); err == nil {
		binPath = resolved
	}

	home, err := resolveHome()
	if err != nil {
		return err
	}
	state, err := stateDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(state, 0o755); err != nil {
		return err
	}

	plist := renderLaunchdPlist(binPath, port, state, home)

	plistPath := filepath.Join(home, "Library", "LaunchAgents", "com.byliu.egress-guard.plist")
	if err := os.MkdirAll(filepath.Dir(plistPath), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(plistPath, []byte(plist), 0o644); err != nil {
		return err
	}
	// Load via launchctl. Unload first to handle re-install case.
	exec.Command("launchctl", "unload", plistPath).Run()
	if out, err := exec.Command("launchctl", "load", plistPath).CombinedOutput(); err != nil {
		// Non-fatal: caller will see the warning but kernel rules already installed.
		return fmt.Errorf("launchctl load: %w (output: %s)", err, out)
	}
	return nil
}

// uninstallLaunchAgent unloads and removes the plist. Idempotent.
func uninstallLaunchAgent() error {
	home, err := resolveHome()
	if err != nil {
		return err
	}
	plistPath := filepath.Join(home, "Library", "LaunchAgents", "com.byliu.egress-guard.plist")
	exec.Command("launchctl", "unload", plistPath).Run() // best-effort
	if err := os.Remove(plistPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
