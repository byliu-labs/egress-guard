//go:build darwin

package cli

import (
	"bytes"
	"strings"
	"testing"
)

// Real launchctl output captured from a running install. Format is the
// classic plist-style dump (not JSON) — the command predates launchctl's
// `print` subcommand and still uses this format on every macOS we support.
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

// Same plist, between KeepAlive restarts: registered with launchd but not
// currently running. The PID line is absent — that's how we distinguish
// "ENABLED but daemon down" from "ENABLED and daemon up".
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

// stubLaunchctl swaps the launchctlList var for the duration of the test.
func stubLaunchctl(t *testing.T, output string, found bool) {
	t.Helper()
	prev := launchctlList
	t.Cleanup(func() { launchctlList = prev })
	launchctlList = func() (string, bool) { return output, found }
}

func stubLaunchctlDaemon(t *testing.T, output string, found bool) {
	t.Helper()
	prev := launchctlListDaemon
	t.Cleanup(func() { launchctlListDaemon = prev })
	launchctlListDaemon = func() (string, bool) { return output, found }
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
	if !strings.Contains(out, "daemon: not running") {
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
	if !strings.Contains(out, "KeepAlive") {
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
	stubLaunchctlDaemon(t, launchctlListRunning, true)
	var buf bytes.Buffer
	if err := printPlatformStatus(&buf); err != nil {
		t.Fatalf("printPlatformStatus: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "LaunchDaemon (boot-resident): ENABLED") {
		t.Errorf("expected LaunchDaemon ENABLED line; got:\n%s", out)
	}
	if !strings.Contains(out, "boot-daemon: running (pid 12345)") {
		t.Errorf("expected boot-daemon pid line; got:\n%s", out)
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
