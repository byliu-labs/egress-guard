//go:build darwin

package menubar

import (
	"fmt"
	"os"
	"strings"

	"github.com/byliu-labs/egress-guard/internal/cli"
)

const (
	installedBinPath = "/usr/local/bin/egress-guard"
	installedBarPath = "/usr/local/bin/egress-guard-bar"
)

var (
	statFn = os.Stat
	// bootDaemonInstalledFn reports whether protection is already installed.
	// It stat-s the system daemon's plist (works unprivileged) rather than the
	// old `com.byliu.egress-guard` agent label, which the current system-daemon
	// architecture never registers — probing that stale label made
	// FirstRunNeeded always true, so every relaunch fired a root prompt.
	bootDaemonInstalledFn = cli.BootDaemonInstalled
)

// osascriptAdmin returns the AppleScript program that runs shellCmd once behind
// a native admin prompt. It is handed to `osascript -e` as a single argv
// element (see osascriptFn) — never through an intermediate /bin/sh -c — so the
// only shell that interprets shellCmd is do-shell-script's own /bin/sh, where
// the single-quoting in AdminInstallScript keeps a crafted bundle path inert.
// AppleScript string literals use double quotes, so backslashes and double
// quotes inside shellCmd must be escaped for the AppleScript layer; `$` and
// backticks are literal in AppleScript strings and need no escaping here.
func osascriptAdmin(shellCmd string) string {
	esc := strings.ReplaceAll(shellCmd, `\`, `\\`)
	esc = strings.ReplaceAll(esc, `"`, `\"`)
	return fmt.Sprintf(`do shell script "%s" with administrator privileges`, esc)
}

// shellSingleQuote wraps s in single quotes safe for POSIX sh, escaping any
// embedded single quote as '\''. AdminInstallScript's output runs as root via
// `osascript ... with administrator privileges`, and binDir comes from the
// app-bundle location (os.Executable). A bundle planted under a path with
// shell metacharacters must not break out of the quoting into a root command.
func shellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// AdminInstallScript is the root-half shell command: place both binaries at a
// stable path and install the pf anchor plus boot-resident daemon.
func AdminInstallScript(binDir string) string {
	src := strings.TrimRight(binDir, "/")
	q := shellSingleQuote
	return strings.Join([]string{
		fmt.Sprintf("cp %s %s", q(src+"/egress-guard"), q(installedBinPath)),
		fmt.Sprintf("cp %s %s", q(src+"/egress-guard-bar"), q(installedBarPath)),
		fmt.Sprintf("chmod +x %s %s", q(installedBinPath), q(installedBarPath)),
		fmt.Sprintf("%s install", q(installedBinPath)),
	}, " && ")
}

// FirstRunNeeded reports whether the app should offer to self-install: the
// stable binary is absent, or the boot-resident system daemon is not installed.
// Both conditions are genuine "not installed yet" states — so once installed,
// routine relaunches return false and never escalate.
func FirstRunNeeded() bool {
	if _, err := statFn(installedBinPath); err != nil {
		return true
	}
	return !bootDaemonInstalledFn()
}

// confirmInstall shows a non-privileged, attributed dialog before any privilege
// escalation. The macOS admin prompt that follows only names "osascript" (the
// interpreter), giving the user no way to tell who is asking or why — the exact
// unattributed-escalation hazard this project targets. Until a code-signed
// helper can raise an OS prompt bearing the app's own identity (see roadmap),
// this preceding dialog supplies the attribution the system prompt lacks, and
// lets the user decline before any password box appears. Returns true only if
// the user explicitly proceeds.
var confirmInstall = func() bool {
	const msg = "egress-guard needs administrator access to install its firewall daemon and copy its binaries into /usr/local/bin.\n\nmacOS will show a password prompt next that only says \"osascript\" — that prompt is this installation. Click Cancel here if you did not just launch egress-guard."
	script := fmt.Sprintf(
		`display dialog %q with title "egress-guard installer" buttons {"Cancel", "Install"} default button "Install" cancel button "Cancel" with icon caution`,
		msg)
	// osascript exits non-zero when the user cancels; zero when Install is clicked.
	return osascriptFn(script) == nil
}
