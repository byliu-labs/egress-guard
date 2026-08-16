//go:build darwin

package persist

import (
	"strings"
	"testing"

	"github.com/byliu-labs/egress-guard/internal/procid"
)

func TestAttribute_NonPersistentKindSkipsLedger(t *testing.T) {
	requireCommand(t, "ps", "-axo", "pid=,ppid=,comm=")

	t.Setenv("XDG_STATE_HOME", t.TempDir())

	src, err := Attribute(procid.ProcInfo{PID: 1, PPID: 1})
	if err != nil {
		if strings.Contains(err.Error(), "operation not permitted") {
			t.Skipf("host process inspection blocked by sandbox: %v", err)
		}
		t.Fatalf("Attribute: %v", err)
	}
	if src.Kind != KindUnknown {
		t.Fatalf("Kind = %q, want %q (pid 1 has no shell/launchd/cron ancestor)", src.Kind, KindUnknown)
	}
	if src.New {
		t.Error("non-persistent source must never be New")
	}
	if !src.FirstSeen.IsZero() {
		t.Error("non-persistent source must not have a FirstSeen")
	}
}
