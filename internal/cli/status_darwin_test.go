//go:build darwin

package cli

import (
	"bytes"
	"strings"
	"testing"
)

// Real `launchctl list` output captured from a running user LaunchAgent.
const launchctlListRunning = `{
	"LimitLoadToSessionType" = "Aqua";
	"Label" = "com.byliu.egress-guard";
	"OnDemand" = false;
	"LastExitStatus" = 0;
	"PID" = 12345;
	"Program" = "/opt/homebrew/bin/egress-guard";
	"ProgramArguments" = (
		"/opt/homebrew/bin/egress-guard";
		"start";
		"--port=8443";
	);
	};`

// Verbatim `launchctl print system/com.byliu.egress-guard.daemon` from a host
// where the daemon is bootstrapped and running. Kept real rather than
// trimmed: the output carries seven other `key = <integer>` lines, and
// `runs = 1` sits directly above `pid = 893`. A hand-written fixture with
// only the pid line would let a loosened regex pass.
const launchctlPrintRunning = `system/com.byliu.egress-guard.daemon = {
	active count = 1
	path = /Library/LaunchDaemons/com.byliu.egress-guard.daemon.plist
	type = LaunchDaemon
	state = running

	program = /usr/local/bin/egress-guard
	arguments = {
		/usr/local/bin/egress-guard
		start
		--port=8443
		--system
	}

	stdout path = /var/db/egress-guard/.local/state/egress-guard/daemon.log
	stderr path = /var/db/egress-guard/.local/state/egress-guard/daemon.err
	default environment = {
		PATH => /usr/bin:/bin:/usr/sbin:/sbin
	}

	environment = {
		OSLogRateLimit => 64
		PATH => /usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin
		HOME => /var/db/egress-guard
		XPC_SERVICE_NAME => com.byliu.egress-guard.daemon
	}

	domain = system
	minimum runtime = 10
	exit timeout = 5
	runs = 1
	pid = 893
	immediate reason = speculative
	forks = 3
	execs = 1
	initialized = 1
	trampolined = 1
	started suspended = 0
	proxy started suspended = 0
	checked allocations = 0 (queried = 1)`

// Verbatim `launchctl print` for a system daemon that is bootstrapped but not
// currently running, relabelled to ours. Captured real because the SHAPE is
// the point: it carries `runs = 1` and nested `state = active` stanzas with
// no pid line anywhere. A parser that reads the wrong numeric line renders
// "boot-daemon: running (pid 1)" for a daemon that is dead — the inverted
// twin of the bug this file exists to prevent.
const launchctlPrintLoadedNotRunning = `system/com.byliu.egress-guard.daemon = {
	active count = 0
	path = /System/Library/LaunchDaemons/com.byliu.egress-guard.daemon.plist
	type = LaunchDaemon
	state = not running

	program = /System/Library/PrivateFrameworks/CoreAccessories.framework/Support/accessoryd
	arguments = {
		/System/Library/PrivateFrameworks/CoreAccessories.framework/Support/accessoryd
	}

	default environment = {
		PATH => /usr/bin:/bin:/usr/sbin:/sbin
	}

	environment = {
		OSLogRateLimit => 64
		MallocSpaceEfficient => 1
		XPC_SERVICE_NAME => com.byliu.egress-guard.daemon
	}

	domain = system
	minimum runtime = 10
	base minimum runtime = 10
	exit timeout = 5
	runs = 1
	last exit reason = JETSAM_REASON_MEMORY_IDLE_EXIT
	last jetsam exit details = JETSAM_REASON_MEMORY_IDLE_EXIT

	event triggers = {
		com.byliu.egress-guard.daemon.matching.A2869.billboard => {
			keepalive = 0`

// User LaunchAgent output between KeepAlive restarts: registered with launchd
// but not currently running.
const launchctlListLoadedNotRunning = `{
	"LimitLoadToSessionType" = "Aqua";
	"Label" = "com.byliu.egress-guard";
	"OnDemand" = false;
	"LastExitStatus" = 1;
	"Program" = "/opt/homebrew/bin/egress-guard";
};`

func TestParseAgentList_RunningExtractsPID(t *testing.T) {
	state := parseAgentList(launchctlListRunning)
	if !state.Loaded {
		t.Error("Loaded should be true when launchctl returned output")
	}
	if state.PID != 12345 {
		t.Errorf("PID = %d, want 12345", state.PID)
	}
}

func TestParseAgentList_LoadedNotRunning(t *testing.T) {
	state := parseAgentList(launchctlListLoadedNotRunning)
	if !state.Loaded {
		t.Error("Loaded should be true even when no PID line — plist is registered")
	}
	if state.PID != 0 {
		t.Errorf("PID = %d, want 0 (no PID line in fixture)", state.PID)
	}
}

func TestParseDaemonPrint_RunningExtractsPID(t *testing.T) {
	state := parseDaemonPrint(launchctlPrintRunning)
	if !state.Loaded {
		t.Fatal("a successful system-domain print means the job is loaded")
	}
	if state.PID != 893 {
		t.Errorf("PID = %d, want 893", state.PID)
	}
}

func TestParseDaemonPrint_LoadedWithoutPID(t *testing.T) {
	state := parseDaemonPrint("system/" + launchDaemonLabel + " = {\n\tstate = waiting\n}")
	if !state.Loaded {
		t.Fatal("a successful system-domain print means the job is loaded")
	}
	if state.PID != 0 {
		t.Errorf("PID = %d, want 0", state.PID)
	}
}

// stubLaunchctl swaps the launchctlList var for the duration of the test.
func stubLaunchctl(t *testing.T, output string, found bool) {
	t.Helper()
	prev := launchctlList
	t.Cleanup(func() { launchctlList = prev })
	launchctlList = func() (string, bool) { return output, found }
}

func stubLaunchctlDaemon(t *testing.T, output string, found bool) {
	t.Helper()
	prev := launchctlPrintDaemon
	t.Cleanup(func() { launchctlPrintDaemon = prev })
	launchctlPrintDaemon = func() (string, bool) { return output, found }
}

func TestPrintPlatformStatus_NotEnabled(t *testing.T) {
	stubLaunchctl(t, "", false)
	stubLaunchctlDaemon(t, "", false)
	var buf bytes.Buffer
	if err := printPlatformStatus(&buf); err != nil {
		t.Fatalf("printPlatformStatus: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "LaunchAgent: NOT enabled") {
		t.Errorf("expected NOT enabled line; got:\n%s", out)
	}
	if !strings.Contains(out, "egress-guard enable") {
		t.Errorf("output should point user at the `enable` command; got:\n%s", out)
	}
	if !hasLine(out, "daemon: not running") {
		t.Errorf("expected daemon-not-running line; got:\n%s", out)
	}
}

func TestPrintPlatformStatus_FullyRunning(t *testing.T) {
	stubLaunchctl(t, launchctlListRunning, true)
	stubLaunchctlDaemon(t, "", false)
	var buf bytes.Buffer
	if err := printPlatformStatus(&buf); err != nil {
		t.Fatalf("printPlatformStatus: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "LaunchAgent: ENABLED") {
		t.Errorf("expected ENABLED line; got:\n%s", out)
	}
	if !strings.Contains(out, "daemon: running (pid 12345)") {
		t.Errorf("expected pid line; got:\n%s", out)
	}
}

func TestPrintPlatformStatus_LoadedButDaemonDown(t *testing.T) {
	stubLaunchctl(t, launchctlListLoadedNotRunning, true)
	stubLaunchctlDaemon(t, "", false)
	var buf bytes.Buffer
	if err := printPlatformStatus(&buf); err != nil {
		t.Fatalf("printPlatformStatus: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "LaunchAgent: ENABLED") {
		t.Errorf("expected ENABLED line; got:\n%s", out)
	}
	// The "KeepAlive should restart" hint is the user-actionable part:
	// without it, "daemon: not running" alongside "LaunchAgent: ENABLED"
	// looks like a contradiction rather than a transient state.
	if !hasLine(out, "daemon: not running (KeepAlive should restart it shortly)") {
		t.Errorf("expected KeepAlive hint when loaded-but-not-running; got:\n%s", out)
	}
}

func TestPrintPlatformStatus_LaunchDaemonNotEnabled(t *testing.T) {
	stubLaunchctl(t, "", false)
	stubLaunchctlDaemon(t, "", false)
	var buf bytes.Buffer
	if err := printPlatformStatus(&buf); err != nil {
		t.Fatalf("printPlatformStatus: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "LaunchDaemon (boot-resident): NOT enabled") {
		t.Errorf("expected LaunchDaemon NOT enabled line; got:\n%s", out)
	}
	if !strings.Contains(out, "sudo egress-guard install") {
		t.Errorf("output should point user at `sudo egress-guard install`; got:\n%s", out)
	}
}

func TestPrintPlatformStatus_LaunchDaemonRunning(t *testing.T) {
	stubLaunchctl(t, "", false)
	stubLaunchctlDaemon(t, launchctlPrintRunning, true)
	// A bootstrapped job is authoritative even if its plist is no longer on
	// disk. Status must key ENABLED on launchd's live system-domain state.
	var buf bytes.Buffer
	if err := printPlatformStatus(&buf); err != nil {
		t.Fatalf("printPlatformStatus: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "LaunchDaemon (boot-resident): ENABLED") {
		t.Errorf("expected LaunchDaemon ENABLED line; got:\n%s", out)
	}
	if !strings.Contains(out, "boot-daemon: running (pid 893)") {
		t.Errorf("expected boot-daemon pid line; got:\n%s", out)
	}
}

func TestPrintPlatformStatus_LoadedWithoutPIDIsNotRunning(t *testing.T) {
	stubLaunchctl(t, "", false)
	stubLaunchctlDaemon(t, launchctlPrintLoadedNotRunning, true)

	var buf bytes.Buffer
	if err := printPlatformStatus(&buf); err != nil {
		t.Fatalf("printPlatformStatus: %v", err)
	}
	out := buf.String()
	// The claim this PR rests on: a job launchd has bootstrapped is ENABLED
	// even while its process is down between KeepAlive restarts. Without this
	// line, keying ENABLED on BootDaemonPID>0 instead of BootDaemonLoaded
	// passes the whole suite while rendering "NOT enabled (run sudo
	// egress-guard install)" over a healthy install.
	if !hasLine(out, "LaunchDaemon (boot-resident): ENABLED") {
		t.Errorf("status = %q; a bootstrapped job is enabled even with no live process", out)
	}
	if !hasLine(out, "boot-daemon: not running (KeepAlive should restart it shortly)") {
		t.Errorf("status = %q, want a queryable not-running observation", out)
	}
}

// Real `route get default` output (en0, normal Wi-Fi default route).
const routeOutputEn0 = `   route to: default
destination: default
       mask: default
    gateway: 192.168.1.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
 recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
       0         0         0         0         0         0      1500         0
`

// Real `route get default` output captured on this machine with sing-box's
// TUN device active. Note the absence of a gateway line — TUN routes are
// point-to-point so `route` omits it.
const routeOutputUtun4 = `   route to: default
destination: default
       mask: default
  interface: utun4
      flags: <UP,DONE,CLONING,STATIC,GLOBAL>
 recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
       0         0         0         0         0         0      4000         0
`

func TestDefaultRouteInterface_ExtractsName(t *testing.T) {
	cases := map[string]struct {
		fixture string
		want    string
	}{
		"en0":     {routeOutputEn0, "en0"},
		"utun4":   {routeOutputUtun4, "utun4"},
		"empty":   {"", ""},
		"garbage": {"no interface line here\n", ""},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			prev := routeGetDefault
			t.Cleanup(func() { routeGetDefault = prev })
			routeGetDefault = func() (string, bool) { return tc.fixture, tc.fixture != "" }
			if got := defaultRouteInterface(); got != tc.want {
				t.Errorf("defaultRouteInterface = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestIsTUNInterface(t *testing.T) {
	tun := []string{"utun0", "utun4", "utun9", "utun42"}
	notTUN := []string{"en0", "en1", "lo0", "bridge100", "", "tun0", "utun"}
	for _, iface := range tun {
		if !isTUNInterface(iface) {
			t.Errorf("isTUNInterface(%q) = false, want true", iface)
		}
	}
	for _, iface := range notTUN {
		if isTUNInterface(iface) {
			t.Errorf("isTUNInterface(%q) = true, want false", iface)
		}
	}
}

func TestTUNProxyWarning_FiresForUtun(t *testing.T) {
	w := tunProxyWarning("utun4")
	if w == "" {
		t.Fatal("tunProxyWarning(utun4) = empty; expected warning text")
	}
	for _, s := range []string{"WARNING", "utun4", "sing-box", "egress-guard", "README"} {
		if !strings.Contains(w, s) {
			t.Errorf("warning missing %q; got:\n%s", s, w)
		}
	}
}

func TestTUNProxyWarning_SilentForRealInterface(t *testing.T) {
	for _, iface := range []string{"en0", "en1", "lo0", ""} {
		if w := tunProxyWarning(iface); w != "" {
			t.Errorf("tunProxyWarning(%q) = %q; want empty (no warning for real interface)", iface, w)
		}
	}
}

// stubRoute swaps the routeGetDefault var.
func stubRoute(t *testing.T, output string, ok bool) {
	t.Helper()
	prev := routeGetDefault
	t.Cleanup(func() { routeGetDefault = prev })
	routeGetDefault = func() (string, bool) { return output, ok }
}

func TestPrintPlatformStatus_TUNWarningWhenDefaultRouteIsTUN(t *testing.T) {
	stubLaunchctl(t, launchctlListRunning, true)
	stubLaunchctlDaemon(t, "", false)
	stubRoute(t, routeOutputUtun4, true)
	var buf bytes.Buffer
	if err := printPlatformStatus(&buf); err != nil {
		t.Fatalf("printPlatformStatus: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "WARNING: default route is via utun4") {
		t.Errorf("expected TUN warning; got:\n%s", out)
	}
}

func TestPrintPlatformStatus_NoTUNWarningWhenDefaultRouteIsReal(t *testing.T) {
	stubLaunchctl(t, launchctlListRunning, true)
	stubLaunchctlDaemon(t, "", false)
	stubRoute(t, routeOutputEn0, true)
	var buf bytes.Buffer
	if err := printPlatformStatus(&buf); err != nil {
		t.Fatalf("printPlatformStatus: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "WARNING") {
		t.Errorf("did not expect TUN warning for en0; got:\n%s", out)
	}
}

func TestPrintPlatformStatus_NoTUNWarningWhenOffline(t *testing.T) {
	stubLaunchctl(t, launchctlListRunning, true)
	stubLaunchctlDaemon(t, "", false)
	stubRoute(t, "", false)
	var buf bytes.Buffer
	if err := printPlatformStatus(&buf); err != nil {
		t.Fatalf("printPlatformStatus: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "WARNING") {
		t.Errorf("offline (no default route) should not fire warning; got:\n%s", out)
	}
}

// hasLine matches a whole output line. `strings.Contains(out, "daemon: not
// running")` is satisfied by the "boot-daemon: not running" line, so a
// substring check on any of these strings cannot fail for the reason it claims.
func hasLine(out, want string) bool {
	for _, line := range strings.Split(out, "\n") {
		if line == want {
			return true
		}
	}
	return false
}

// A plist without a successful system-domain print is not proof that the job
// is loaded. This is the failed-bootstrap state.
func TestPrintPlatformStatus_PlistWithoutALoadedJobIsNotEnabled(t *testing.T) {
	stubLaunchctl(t, "", false)
	stubLaunchctlDaemon(t, "", false)

	var buf bytes.Buffer
	if err := printPlatformStatus(&buf); err != nil {
		t.Fatalf("printPlatformStatus: %v", err)
	}
	out := buf.String()
	if hasLine(out, "LaunchDaemon (boot-resident): ENABLED") {
		t.Errorf("status = %q; no job answered, so a file on disk is not proof of protection", out)
	}
	if !hasLine(out, "LaunchDaemon (boot-resident): NOT enabled (run `sudo egress-guard install`)") {
		t.Errorf("status = %q; no live system-domain job was confirmed", out)
	}
	// The second line of this state was uncovered: mutating it to arbitrary
	// text left the whole package green.
	if !hasLine(out, "boot-daemon: not running") {
		t.Errorf("status = %q; no job answered, so there is no live process", out)
	}
}

// A job that actually answered is the only thing that earns the word ENABLED.
func TestPrintPlatformStatus_QueryableJobEarnsEnabled(t *testing.T) {
	stubLaunchctl(t, "", false)
	stubLaunchctlDaemon(t, launchctlPrintRunning, true)

	var buf bytes.Buffer
	if err := printPlatformStatus(&buf); err != nil {
		t.Fatalf("printPlatformStatus: %v", err)
	}
	if out := buf.String(); !hasLine(out, "LaunchDaemon (boot-resident): ENABLED") {
		t.Errorf("status = %q, want ENABLED for a job launchd confirmed", out)
	}
}
