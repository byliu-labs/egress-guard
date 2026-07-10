//go:build darwin

package menubar

import (
	"fmt"
	"os/exec"
	"regexp"
)

// osascriptFn runs an AppleScript program directly via osascript's argv, with
// no intermediate /bin/sh -c. Bypassing an outer shell is a security boundary:
// it ensures the only shell that ever interprets the wrapped command is
// do-shell-script's own /bin/sh, so a crafted bundle path cannot be
// command-substituted ($()/backticks) by an outer shell before the
// single-quoting in AdminInstallScript can neutralize it.
var osascriptFn = func(appleScript string) error {
	return exec.Command("osascript", "-e", appleScript).Run()
}

var execFn = func(name string, args ...string) error {
	return exec.Command(name, args...).Run()
}

// UninstallScriptRoot is the root half of a clean uninstall: remove the pf
// anchor plus boot-resident daemon, then delete both stable binaries.
func UninstallScriptRoot() string {
	return fmt.Sprintf("%s uninstall ; rm -f %s %s",
		installedBinPath, installedBinPath, installedBarPath)
}

// PauseScript flushes the egress-guard pf anchor; the daemon stays up but
// enforces nothing until resumed.
func PauseScript() string {
	return "pfctl -a egress-guard -F all"
}

// ResumeScript rewrites the pf anchor from the daemon's rules.
func ResumeScript() string {
	return fmt.Sprintf("%s install", installedBinPath)
}

// RunAdmin runs an internal, constant shell command behind one native admin
// prompt. Callers must not pass log-derived or user-supplied data here.
func RunAdmin(shellCmd string) error {
	return osascriptFn(osascriptAdmin(shellCmd))
}

var hostRe = regexp.MustCompile(`^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*$`)

func validHost(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	return hostRe.MatchString(host)
}

// AllowHost adds a host to the user allowlist. The host can originate from
// attacker-controlled SNI in the decision log, so it is validated and passed as
// direct argv, never through a shell.
func AllowHost(host string) error {
	if !validHost(host) {
		return fmt.Errorf("refusing to allow invalid host %q", host)
	}
	return execFn(installedBinPath, "allow", host)
}
