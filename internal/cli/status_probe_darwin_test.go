//go:build darwin

package cli

import "testing"

func TestProbe_RunningDaemonNoTUN(t *testing.T) {
	orig := launchctlList
	origDaemon := launchctlPrintDaemon
	origRoute := routeGetDefault
	t.Cleanup(func() {
		launchctlList = orig
		launchctlPrintDaemon = origDaemon
		routeGetDefault = origRoute
	})

	launchctlList = func() (string, bool) {
		return "{\n\t\"PID\" = 12345;\n\t\"Label\" = \"com.byliu.egress-guard\";\n};", true
	}
	launchctlPrintDaemon = func() (string, bool) { return "", false }
	routeGetDefault = func() (string, bool) { return "   interface: en0\n", true }

	got := Probe()
	if !got.AgentLoaded {
		t.Fatalf("expected AgentLoaded=true")
	}
	if got.DaemonPID != 12345 {
		t.Errorf("DaemonPID = %d, want 12345", got.DaemonPID)
	}
	if got.TUNIface != "" {
		t.Errorf("TUNIface = %q, want empty", got.TUNIface)
	}
}

func TestProbe_TUNBypass(t *testing.T) {
	origRoute := routeGetDefault
	origList := launchctlList
	origDaemon := launchctlPrintDaemon
	t.Cleanup(func() {
		routeGetDefault = origRoute
		launchctlList = origList
		launchctlPrintDaemon = origDaemon
	})

	launchctlList = func() (string, bool) { return "", false }
	launchctlPrintDaemon = func() (string, bool) { return "", false }
	routeGetDefault = func() (string, bool) { return "   interface: utun4\n", true }

	got := Probe()
	if got.TUNIface != "utun4" {
		t.Errorf("TUNIface = %q, want utun4", got.TUNIface)
	}
	if got.AgentLoaded {
		t.Errorf("AgentLoaded = true, want false")
	}
}
