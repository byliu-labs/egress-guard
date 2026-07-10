package cli

import (
	"path/filepath"
	"testing"
)

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
