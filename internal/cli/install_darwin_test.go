//go:build darwin

package cli

import (
	"strings"
	"testing"
)

func TestRenderLaunchdPlist_SubstitutesAllPlaceholders(t *testing.T) {
	got := renderLaunchdPlist(
		"/opt/homebrew/bin/egress-guard",
		8443,
		"/Users/alice/.local/state/egress-guard",
		"/Users/alice",
	)

	if strings.Contains(got, "{{") {
		t.Errorf("rendered plist still contains template placeholders:\n%s", got)
	}

	mustContain := []string{
		`<string>/opt/homebrew/bin/egress-guard</string>`,
		`<string>--port=8443</string>`,
		`<string>/Users/alice/.local/state/egress-guard/daemon.log</string>`,
		`<string>/Users/alice/.local/state/egress-guard/daemon.err</string>`,
	}
	for _, s := range mustContain {
		if !strings.Contains(got, s) {
			t.Errorf("rendered plist missing %q", s)
		}
	}
}

func TestRenderLaunchdPlist_HasEnvironmentVariables(t *testing.T) {
	got := renderLaunchdPlist("/bin/eg", 8443, "/state", "/Users/bob")

	// EnvironmentVariables block must exist with HOME and PATH.
	if !strings.Contains(got, "<key>EnvironmentVariables</key>") {
		t.Fatal("rendered plist missing <key>EnvironmentVariables</key>")
	}
	if !strings.Contains(got, "<key>HOME</key>\n        <string>/Users/bob</string>") {
		t.Errorf("rendered plist missing HOME=/Users/bob in EnvironmentVariables; got:\n%s", got)
	}
	// PATH must include both Homebrew prefixes for portability across Apple Silicon and Intel.
	if !strings.Contains(got, "/opt/homebrew/bin") {
		t.Error("PATH missing /opt/homebrew/bin (Apple Silicon Homebrew default)")
	}
	if !strings.Contains(got, "/usr/local/bin") {
		t.Error("PATH missing /usr/local/bin (Intel Homebrew default)")
	}
	// PATH must include the canonical macOS locations of every binary the
	// daemon shells out to. Without these, launchd's restricted env causes
	// silent regressions: lsof at /usr/sbin/lsof drives process identity
	// (procid_darwin.go), and pfctl at /sbin/pfctl drives kernel-rule
	// status checks (kernel/pf_darwin.go).
	for _, p := range []string{"/usr/bin", "/bin", "/usr/sbin", "/sbin"} {
		if !strings.Contains(got, p) {
			t.Errorf("PATH missing %s — required for binaries the daemon execs by name", p)
		}
	}
	// System tool directories must come BEFORE Homebrew prefixes. The daemon
	// shells out to lsof/ps/codesign/osascript by name, and under the current
	// root LaunchAgent install path runs with root privileges; a Homebrew-
	// shadowed binary in /opt/homebrew/bin would otherwise be picked up
	// instead of the macOS system tool.
	systemFirst := strings.Index(got, "/usr/bin")
	homebrewIdx := strings.Index(got, "/opt/homebrew/bin")
	if systemFirst < 0 || homebrewIdx < 0 || systemFirst > homebrewIdx {
		t.Errorf("PATH must put system dirs before Homebrew (system=%d, homebrew=%d): security-sensitive ordering",
			systemFirst, homebrewIdx)
	}
}

func TestEnable_NoOpsWhenLaunchDaemonAlreadyInstalled(t *testing.T) {
	stubEuid(t, 501)
	prev := launchDaemonInstalled
	t.Cleanup(func() { launchDaemonInstalled = prev })
	launchDaemonInstalled = func() bool { return true }

	if err := Enable(nil); err != nil {
		t.Fatalf("Enable: %v", err)
	}
}
