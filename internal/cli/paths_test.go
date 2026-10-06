package cli

import (
	"path/filepath"
	"testing"
)

func TestRejectedPairsPathUsesInstalledDaemonOverride(t *testing.T) {
	want := filepath.Join(t.TempDir(), "rejected-pairs.jsonl")
	t.Setenv("EGRESS_GUARD_REJECTION_PATH", want)
	got, err := RejectedPairsPath()
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("rejection path=%q, want %q", got, want)
	}
}

func TestBlockLogPath_UsesStateDir(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", "/tmp/eg-state")
	got, err := BlockLogPath()
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join("/tmp/eg-state", "egress-guard", "blocked.log")
	if got != want {
		t.Errorf("BlockLogPath() = %q, want %q", got, want)
	}
}
