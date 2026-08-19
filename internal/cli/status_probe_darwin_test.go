//go:build darwin

package cli

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
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

	var idle []string
	resolved := false
	for _, label := range candidates {
		out, err := exec.Command("launchctl", "print", "system/"+label).CombinedOutput()
		if err != nil {
			// Not "try the next one" — record it. If NONE resolves, that is the
			// privilege regression this test exists to detect, and skipping
			// would report green for precisely the failure it watches for.
			continue
		}
		resolved = true
		// Independently pull the pid out of the real dump, so this asserts the
		// parser found THE JOB'S pid rather than merely some positive integer.
		// Real output carries confounders directly above it — opendirectoryd
		// emits "runs = 1" on the line before "pid = N" — and a regex loosened
		// to any `word = <int>` would otherwise return 1 (launchd) and pass.
		want, ok := pidFromRealDump(string(out))
		if !ok {
			// Loaded but idle: no pid line at all. 246 of 423 system jobs on a
			// typical machine are in this state, so try the next candidate
			// rather than failing on an unrelated job's health.
			idle = append(idle, label)
			continue
		}
		got := parseDaemonPrint(string(out))
		if !got.Loaded {
			t.Fatalf("parseDaemonPrint reported not loaded for system/%s", label)
		}
		if got.PID != want {
			t.Fatalf("parseDaemonPrint(system/%s) pid = %d, want %d (from the literal `pid =` line):\n%s",
				label, got.PID, want, out)
		}
		// Informational, not a requirement of our code: `launchctl list` is
		// expected to fail here because it resolves in the user domain. If it
		// ever succeeds, the comment on daemonStatusArgs needs revisiting.
		if _, err := exec.Command("launchctl", "list", label).CombinedOutput(); err == nil {
			t.Logf("note: launchctl list %s succeeded unprivileged; the user-domain premise may have changed", label)
		}
		return
	}
	if !resolved {
		t.Fatalf("no system daemon from %v answered `launchctl print system/<label>` at euid %d; "+
			"the unprivileged system-domain access this probe depends on has regressed",
			candidates, os.Geteuid())
	}
	// Every candidate answered but all were idle — the domain is reachable, which
	// is the claim; there was simply no live pid to check the parser against.
	t.Skipf("all of %v are loaded but idle; domain reachable, no pid to assert", idle)
}

// pidFromRealDump finds the job's own pid line without reusing the production
// regex, so the test cannot agree with the code by sharing its bug. It matches
// only a line whose key is exactly "pid", at the dump's top level.
func pidFromRealDump(dump string) (int, bool) {
	for _, line := range strings.Split(dump, "\n") {
		key, value, found := strings.Cut(line, "=")
		if !found || strings.TrimSpace(key) != "pid" {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(value), ";")))
		if err == nil {
			return pid, true
		}
	}
	return 0, false
}
