//go:build darwin

package menubar

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestOsascriptAdmin_EscapesQuotes(t *testing.T) {
	got := osascriptAdmin(`cp "/a b/x" /usr/local/bin/x`)
	if !strings.HasPrefix(got, `do shell script "`) {
		t.Errorf("missing do-shell-script prefix: %q", got)
	}
	if !strings.Contains(got, "with administrator privileges") {
		t.Errorf("missing admin clause: %q", got)
	}
	if !strings.Contains(got, `\"/a b/x\"`) {
		t.Errorf("inner double-quotes not escaped for AppleScript: %q", got)
	}
	// The result is passed to osascript via argv (osascriptFn), so it must NOT
	// re-wrap itself in an outer `osascript -e "…"` shell string — that outer
	// /bin/sh layer was the command-substitution injection vector.
	if strings.Contains(got, "osascript -e") {
		t.Errorf("must not embed an outer osascript shell wrapper: %q", got)
	}
}

func TestAdminInstallScript_CopiesBothAndInstalls(t *testing.T) {
	s := AdminInstallScript("/Apps/EgressGuard.app/Contents/Resources")
	for _, want := range []string{
		"/Apps/EgressGuard.app/Contents/Resources/egress-guard",
		"/Apps/EgressGuard.app/Contents/Resources/egress-guard-bar",
		"/usr/local/bin/egress-guard",
		"/usr/local/bin/egress-guard-bar",
		"'/usr/local/bin/egress-guard' install",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("script missing %q\nscript: %s", want, s)
		}
	}
}

// shellSingleQuote is the sole barrier between an attacker-planted bundle path
// and a root shell (AdminInstallScript runs via osascript with admin privs).
// Prove the quoting neutralizes metacharacters by running each quoted form
// through a real /bin/sh and asserting it prints back the literal input.
func TestShellSingleQuote_NeutralizesMetacharacters(t *testing.T) {
	for _, in := range []string{
		`plain`,
		`a'b`,
		`x'; touch /tmp/egress_guard_pwned; '`,
		"x`whoami`",
		`x$(id)`,
		`x; rm -rf /`,
		`x && curl evil`,
		`a "b" c`,
		`/Users/o'brien/App.app/Contents/Resources`,
	} {
		quoted := shellSingleQuote(in)
		out, err := exec.Command("/bin/sh", "-c", "printf %s "+quoted).Output()
		if err != nil {
			t.Fatalf("sh rejected quoted %q (=%s): %v", in, quoted, err)
		}
		if string(out) != in {
			t.Errorf("shellSingleQuote(%q) → sh printed %q, want the literal input", in, string(out))
		}
	}
}

// A malicious bundle path must be embedded in escaped form, never as a raw
// breakout that would run as a separate root command.
func TestAdminInstallScript_EscapesMaliciousPath(t *testing.T) {
	s := AdminInstallScript(`/tmp/x'; touch /tmp/egress_guard_pwned; '`)
	if !strings.Contains(s, `'\''`) {
		t.Errorf("expected POSIX single-quote escaping in script:\n%s", s)
	}
	// The injected `touch` must remain inside quotes (preceded by the escape
	// sequence), not sit as a bare command between ` && ` separators.
	if strings.Contains(s, "&& touch /tmp/egress_guard_pwned") {
		t.Errorf("metacharacter path broke out of quoting:\n%s", s)
	}
}

func TestFirstRunNeeded(t *testing.T) {
	origStat, origBoot := statFn, bootDaemonInstalledFn
	t.Cleanup(func() { statFn = origStat; bootDaemonInstalledFn = origBoot })

	// Installed: binary present AND boot daemon installed → no first run, no
	// escalation. This is the case that regressed: the old agent-label probe
	// made this true on every launch, firing a root prompt each time.
	statFn = func(string) (os.FileInfo, error) { return nil, nil }
	bootDaemonInstalledFn = func() bool { return true }
	if FirstRunNeeded() {
		t.Errorf("expected FirstRunNeeded=false when installed (binary + boot daemon present)")
	}

	statFn = func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
	bootDaemonInstalledFn = func() bool { return true }
	if !FirstRunNeeded() {
		t.Errorf("expected FirstRunNeeded=true when binary missing")
	}

	statFn = func(string) (os.FileInfo, error) { return nil, nil }
	bootDaemonInstalledFn = func() bool { return false }
	if !FirstRunNeeded() {
		t.Errorf("expected FirstRunNeeded=true when boot daemon not installed")
	}
}
