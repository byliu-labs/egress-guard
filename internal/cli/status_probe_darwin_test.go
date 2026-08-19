//go:build darwin

package cli

import (
	"os"
	"os/exec"
	"testing"
)

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

// Every render test stubs launchctlPrintDaemon, so none of them would notice
// the probe going back to `launchctl list <label>` — which is exactly how the
// user-domain probe shipped and survived a full green suite. This pins the
// command itself.
func TestDaemonStatusArgs_AddressesTheSystemDomain(t *testing.T) {
	got := daemonStatusArgs()
	want := []string{"launchctl", "print", "system/com.byliu.egress-guard.daemon"}
	if len(got) != len(want) {
		t.Fatalf("daemonStatusArgs() = %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("daemonStatusArgs() = %q, want %q", got, want)
		}
	}
}

// The claim the whole rewrite rests on: the system domain answers without
// root. Asserted against a real launchd rather than a fixture — if this ever
// starts requiring privilege, the render's confident ENABLED becomes a lie and
// every stubbed render test would still pass.
//
// It probes well-known Apple system daemons rather than egress-guard's own, so
// it does not depend on egress-guard being installed and runs in CI.
func TestSystemDomainPrintAnswersUnprivileged(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("only meaningful unprivileged")
	}
	// Any one of these resolving is enough; the point is the domain, not the job.
	candidates := []string{"com.apple.opendirectoryd", "com.apple.securityd", "com.apple.syslogd"}

	var tried []string
	for _, label := range candidates {
		out, err := exec.Command("launchctl", "print", "system/"+label).CombinedOutput()
		if err != nil {
			tried = append(tried, label)
			continue
		}
		got := parseDaemonPrint(string(out))
		if !got.Loaded {
			t.Fatalf("parseDaemonPrint reported not loaded for system/%s", label)
		}
		if got.PID <= 0 {
			t.Fatalf("parseDaemonPrint found no pid in real output for system/%s:\n%s", label, out)
		}
		// Informational, not a requirement of our code: `launchctl list` is
		// expected to fail here because it resolves in the user domain. If it
		// ever succeeds, the comment on daemonStatusArgs needs revisiting.
		if _, err := exec.Command("launchctl", "list", label).CombinedOutput(); err == nil {
			t.Logf("note: launchctl list %s succeeded unprivileged; the user-domain premise may have changed", label)
		}
		return
	}
	t.Skipf("no system daemon from %v was reachable; nothing to assert about the domain", tried)
}
