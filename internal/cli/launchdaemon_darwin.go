//go:build darwin

package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	launchDaemonLabel     = "com.byliu.egress-guard.daemon"
	launchDaemonPlistPath = "/Library/LaunchDaemons/com.byliu.egress-guard.daemon.plist"
	systemStateHome       = "/var/db/egress-guard"
	systemToolsPATH       = "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin"
)

const launchDaemonTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{{LABEL}}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{{BINARY}}</string>
        <string>start</string>
        <string>--port={{PORT}}</string>
        <string>--system</string>
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
        <string>{{SYSPATH}}</string>
    </dict>
    <key>StandardOutPath</key>
    <string>{{STATE}}/daemon.log</string>
    <key>StandardErrorPath</key>
    <string>{{STATE}}/daemon.err</string>
</dict>
</plist>
`

// BootDaemonInstalled reports whether the boot-resident system daemon's plist
// exists. It remains useful for install/catalog gating, but it is not live
// status: the plist can outlive a failed bootstrap, and a bootstrapped job can
// outlive a removed plist. Status queries `launchctl print system/<label>`.
func BootDaemonInstalled() bool {
	return launchDaemonInstalled()
}

// SystemBlockLogPath is where the boot-resident system daemon writes its
// decision log. Under launchd it runs with HOME=systemStateHome, so stateDir()
// resolves here. The menu bar (running as the logged-in user) reads this so it
// reflects the process that actually enforces, not its own ~/.local/state copy.
func SystemBlockLogPath() string {
	return filepath.Join(systemStateHome, ".local", "state", "egress-guard", "blocked.log")
}

func systemBaselineCatalogPath() (string, error) {
	return filepath.Join(systemStateHome, ".config", "egress-guard", "catalog-baseline.toml"), nil
}

func renderLaunchDaemonPlist(binPath string, port int, state string) string {
	return strings.NewReplacer(
		"{{LABEL}}", launchDaemonLabel,
		"{{BINARY}}", binPath,
		"{{PORT}}", fmt.Sprintf("%d", port),
		"{{STATE}}", state,
		"{{HOME}}", systemStateHome,
		"{{SYSPATH}}", systemToolsPATH,
	).Replace(launchDaemonTemplate)
}

func installLaunchDaemon(port int) error {
	binPath, err := os.Executable()
	if err != nil {
		return err
	}
	if resolved, err := filepath.EvalSymlinks(binPath); err == nil {
		binPath = resolved
	}

	state := filepath.Join(systemStateHome, ".local", "state", "egress-guard")
	if err := os.MkdirAll(state, 0o755); err != nil {
		return fmt.Errorf("launchdaemon: create state dir: %w", err)
	}

	plist := renderLaunchDaemonPlist(binPath, port, state)
	if err := os.MkdirAll(filepath.Dir(launchDaemonPlistPath), 0o755); err != nil {
		return fmt.Errorf("launchdaemon: create %s: %w", filepath.Dir(launchDaemonPlistPath), err)
	}
	if err := os.WriteFile(launchDaemonPlistPath, []byte(plist), 0o644); err != nil {
		return fmt.Errorf("launchdaemon: write plist: %w", err)
	}

	exec.Command("launchctl", "bootout", "system/"+launchDaemonLabel).Run()
	if out, err := exec.Command("launchctl", "bootstrap", "system", launchDaemonPlistPath).CombinedOutput(); err != nil {
		return fmt.Errorf("launchdaemon: launchctl bootstrap: %w (output: %s)", err, out)
	}
	return nil
}

func uninstallLaunchDaemon() error {
	exec.Command("launchctl", "bootout", "system/"+launchDaemonLabel).Run()
	if err := os.Remove(launchDaemonPlistPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("launchdaemon: remove plist: %w", err)
	}
	return nil
}

var launchDaemonInstalled = func() bool {
	_, err := os.Stat(launchDaemonPlistPath)
	return err == nil
}
