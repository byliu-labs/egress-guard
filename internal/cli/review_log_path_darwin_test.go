//go:build darwin

package cli

import (
	"testing"
)

func TestReviewLogPathUsesBootDaemonHistory(t *testing.T) {
	old := launchDaemonInstalled
	launchDaemonInstalled = func() bool { return true }
	t.Cleanup(func() { launchDaemonInstalled = old })
	t.Setenv("XDG_STATE_HOME", "")
	if got, err := reviewLogPath(); err != nil || got != SystemBlockLogPath() {
		t.Fatalf("review log = %q, %v; want boot daemon log", got, err)
	}
}

func TestReviewLogPathKeepsExplicitFixtureState(t *testing.T) {
	old := launchDaemonInstalled
	launchDaemonInstalled = func() bool { return true }
	t.Cleanup(func() { launchDaemonInstalled = old })
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	got, err := reviewLogPath()
	if err != nil {
		t.Fatal(err)
	}
	user, err := BlockLogPath()
	if err != nil {
		t.Fatal(err)
	}
	if got != user {
		t.Fatalf("explicit state log = %q; want %q", got, user)
	}
}
