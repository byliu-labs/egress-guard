//go:build darwin

package menubar

import (
	"os"
	"strings"
	"testing"
)

func TestUninstallScriptRoot(t *testing.T) {
	s := UninstallScriptRoot()
	for _, want := range []string{
		"/usr/local/bin/egress-guard uninstall",
		"rm -f",
		"/usr/local/bin/egress-guard-bar",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in %q", want, s)
		}
	}
}

func TestPauseResumeScripts(t *testing.T) {
	if !strings.Contains(PauseScript(), "pfctl -a egress-guard -F all") {
		t.Errorf("PauseScript wrong: %q", PauseScript())
	}
	if !strings.Contains(ResumeScript(), "/usr/local/bin/egress-guard install") {
		t.Errorf("ResumeScript wrong: %q", ResumeScript())
	}
}

func TestRunAdmin_InvokesOsascriptDirectly(t *testing.T) {
	orig := osascriptFn
	t.Cleanup(func() { osascriptFn = orig })
	var captured string
	osascriptFn = func(script string) error { captured = script; return nil }
	if err := RunAdmin("echo hi"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(captured, "with administrator privileges") {
		t.Errorf("RunAdmin did not build an admin AppleScript: %q", captured)
	}
	// The AppleScript goes to osascript's argv, not an outer shell, so it must
	// not carry an `osascript -e "…"` wrapper of its own.
	if strings.Contains(captured, "osascript -e") {
		t.Errorf("RunAdmin must not re-wrap in an outer osascript shell: %q", captured)
	}
}

// A bundle path carrying a command substitution must reach osascript as inert
// data. The old code routed the osascript invocation through `/bin/sh -c`,
// whose double-quoted argument let the OUTER shell expand $(...) before the
// inner single-quoting applied. RunAdmin now calls osascript via argv, so the
// substitution is never expanded by any shell in the Go process's control.
func TestRunAdmin_NoOuterShellCommandSubstitution(t *testing.T) {
	orig := osascriptFn
	t.Cleanup(func() { osascriptFn = orig })
	var captured string
	osascriptFn = func(script string) error { captured = script; return nil }

	marker := "/tmp/egress_guard_outer_pwned_test"
	_ = os.Remove(marker)
	t.Cleanup(func() { _ = os.Remove(marker) })

	if err := RunAdmin(AdminInstallScript("/tmp/x$(touch " + marker + ")/r")); err != nil {
		t.Fatal(err)
	}
	// The substitution survives verbatim as data inside the AppleScript...
	if !strings.Contains(captured, "$(touch "+marker+")") {
		t.Errorf("command substitution was altered/expanded, want it verbatim: %q", captured)
	}
	// ...and nothing executed it.
	if _, err := os.Stat(marker); err == nil {
		t.Errorf("command substitution executed — marker %s was created", marker)
	}
}

func TestAllowHost_DirectArgvNoShell(t *testing.T) {
	orig := execFn
	t.Cleanup(func() { execFn = orig })
	var gotName string
	var gotArgs []string
	execFn = func(name string, args ...string) error {
		gotName = name
		gotArgs = args
		return nil
	}
	if err := AllowHost("pypi.org"); err != nil {
		t.Fatal(err)
	}
	if gotName != installedBinPath {
		t.Errorf("exec name = %q, want %q", gotName, installedBinPath)
	}
	if len(gotArgs) != 2 || gotArgs[0] != "allow" || gotArgs[1] != "pypi.org" {
		t.Errorf("exec args = %v, want [allow pypi.org]", gotArgs)
	}
}

func TestAllowHost_RejectsInjection(t *testing.T) {
	orig := execFn
	t.Cleanup(func() { execFn = orig })
	called := false
	execFn = func(string, ...string) error { called = true; return nil }
	for _, bad := range []string{
		"x.com; rm -rf ~",
		"x.com`whoami`",
		"x.com$(id)",
		"x.com && curl evil",
		"-flag.example.com",
		"",
		"has space.com",
	} {
		if err := AllowHost(bad); err == nil {
			t.Errorf("AllowHost(%q) = nil error, want rejection", bad)
		}
	}
	if called {
		t.Errorf("execFn must never run for an invalid host")
	}
}

func TestValidHost(t *testing.T) {
	good := []string{"pypi.org", "files.pythonhosted.org", "a.b-c.example.com", "xn--nxasmq6b.example"}
	bad := []string{"x.com; rm", "x.com`id`", "-lead.com", "", "has space", strings.Repeat("a", 254)}
	for _, h := range good {
		if !validHost(h) {
			t.Errorf("validHost(%q) = false, want true", h)
		}
	}
	for _, h := range bad {
		if validHost(h) {
			t.Errorf("validHost(%q) = true, want false", h)
		}
	}
}
