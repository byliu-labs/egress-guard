//go:build darwin

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteAndBootstrapLaunchDaemonPlist_RemovesNewFileOnFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.plist")
	bootstrapErr := errors.New("bootstrap failed")

	err := writeAndBootstrapLaunchDaemonPlist(path, []byte("new"), func(string) ([]byte, error) {
		return []byte("launchctl output"), bootstrapErr
	})
	if err == nil {
		t.Fatal("writeAndBootstrapLaunchDaemonPlist succeeded, want bootstrap failure")
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("plist stat error = %v, want file removed", statErr)
	}
}

func TestWriteAndBootstrapLaunchDaemonPlist_RestoresPreviousFileOnFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.plist")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}

	err := writeAndBootstrapLaunchDaemonPlist(path, []byte("new"), func(string) ([]byte, error) {
		return nil, errors.New("bootstrap failed")
	})
	if err == nil {
		t.Fatal("writeAndBootstrapLaunchDaemonPlist succeeded, want bootstrap failure")
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(got) != "old" {
		t.Fatalf("restored plist = %q, want %q", got, "old")
	}
}

func TestRenderLaunchDaemonPlist_SubstitutesAllPlaceholders(t *testing.T) {
	got := renderLaunchDaemonPlist(
		"/opt/homebrew/bin/egress-guard",
		8443,
		"/var/db/egress-guard/.local/state/egress-guard",
	)

	if strings.Contains(got, "{{") {
		t.Errorf("rendered plist still contains template placeholders:\n%s", got)
	}
	for _, s := range []string{
		"<string>com.byliu.egress-guard.daemon</string>",
		"<string>/opt/homebrew/bin/egress-guard</string>",
		"<string>--port=8443</string>",
		"<string>--system</string>",
		"<string>/var/db/egress-guard/.local/state/egress-guard/daemon.log</string>",
	} {
		if !strings.Contains(got, s) {
			t.Errorf("rendered plist missing %q", s)
		}
	}
}

func TestRenderLaunchDaemonPlist_NoUserNameKey(t *testing.T) {
	got := renderLaunchDaemonPlist("/bin/eg", 8443, "/state")
	if strings.Contains(got, "<key>UserName</key>") {
		t.Error("LaunchDaemon plist must not set UserName because the daemon needs root for /dev/pf")
	}
}

func TestRenderLaunchDaemonPlist_DistinctLabelFromLaunchAgent(t *testing.T) {
	daemonPlist := renderLaunchDaemonPlist("/bin/eg", 8443, "/state")
	agentPlist := renderLaunchdPlist("/bin/eg", 8443, "/state", "/Users/alice")
	if strings.Contains(daemonPlist, "<string>com.byliu.egress-guard</string>") {
		t.Error("LaunchDaemon plist must use its own label")
	}
	if !strings.Contains(agentPlist, "<string>com.byliu.egress-guard</string>") {
		t.Error("sanity check: LaunchAgent template regressed")
	}
}

func TestLaunchDaemonInstalled_CallableAndDefaultsFalseInCI(t *testing.T) {
	if launchDaemonInstalled() {
		t.Skip("a real LaunchDaemon is installed on this machine")
	}
}
