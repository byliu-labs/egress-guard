//go:build darwin

package cli

import (
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// agentState captures launchd registration. The user LaunchAgent is read with
// `launchctl list`; the system LaunchDaemon is read with
// `launchctl print system/<label>`. Loaded means the job answered in its
// domain; PID is 0 when loaded but not currently running.
type agentState struct {
	Loaded bool
	PID    int
}

// launchctlList shells out to `launchctl list com.byliu.egress-guard`. The
// command exits non-zero when the label isn't registered in any reachable
// domain. Pulled into a var so tests can substitute fixture output without
// requiring launchd or a loaded plist.
var launchctlList = func() (output string, found bool) {
	out, err := exec.Command("launchctl", "list", "com.byliu.egress-guard").CombinedOutput()
	if err != nil {
		return "", false
	}
	return string(out), true
}

var launchctlPrintDaemon = func() (output string, found bool) {
	// `launchctl print system/...` addresses the system domain directly and is
	// readable by the unprivileged status command. `launchctl list <label>`
	// would query the caller's user domain instead.
	out, err := exec.Command("launchctl", "print", "system/"+launchDaemonLabel).CombinedOutput()
	if err != nil {
		return "", false
	}
	return string(out), true
}

// pidLineRe matches the `"PID" = 12345;` line in launchctl's plist-style
// dump. The line is absent when the agent is loaded but not currently
// running, which is how we distinguish "ENABLED but daemon down" from
// "ENABLED and daemon up".
var pidLineRe = regexp.MustCompile(`"PID"\s*=\s*(\d+)`)
var daemonPIDLineRe = regexp.MustCompile(`(?m)^\s*(?:pid|"PID")\s*=\s*(\d+)\s*;?\s*$`)

func parseAgentList(s string) agentState {
	state := agentState{Loaded: true}
	if m := pidLineRe.FindStringSubmatch(s); m != nil {
		if pid, err := strconv.Atoi(m[1]); err == nil {
			state.PID = pid
		}
	}
	return state
}

func checkAgent() agentState {
	out, found := launchctlList()
	if !found {
		return agentState{}
	}
	return parseAgentList(out)
}

func parseDaemonPrint(s string) agentState {
	state := agentState{Loaded: true}
	if m := daemonPIDLineRe.FindStringSubmatch(s); m != nil {
		if pid, err := strconv.Atoi(m[1]); err == nil {
			state.PID = pid
		}
	}
	return state
}

func checkDaemonJob() agentState {
	out, found := launchctlPrintDaemon()
	if !found {
		return agentState{}
	}
	return parseDaemonPrint(out)
}

// routeGetDefault shells out to `route get default` and returns its stdout.
// On a normal interface (en0) the second-to-last line is `interface: en0`;
// on a TUN-mode transparent proxy (sing-box / ClashX / V2Ray exit node) it
// becomes `interface: utun4`. Pulled into a var so tests can swap fixtures.
var routeGetDefault = func() (output string, ok bool) {
	out, err := exec.Command("route", "get", "default").CombinedOutput()
	if err != nil {
		// Offline (no default route) returns non-zero. Treat as "no info";
		// callers suppress the warning rather than reporting a false positive.
		return "", false
	}
	return string(out), true
}

var routeInterfaceRe = regexp.MustCompile(`(?m)^\s*interface:\s*(\S+)\s*$`)

// defaultRouteInterface returns the interface name on the default route, or
// an empty string if no default route exists.
func defaultRouteInterface() string {
	out, ok := routeGetDefault()
	if !ok {
		return ""
	}
	if m := routeInterfaceRe.FindStringSubmatch(out); m != nil {
		return m[1]
	}
	return ""
}

var tunInterfaceRe = regexp.MustCompile(`^utun\d+$`)

// isTUNInterface reports whether the interface name belongs to a userspace
// TUN device — utun0..utunN. Real interfaces (en0, en1, lo0, bridge100)
// don't match. Tailscale's utun is matched too, but Tailscale only takes
// the default route in exit-node mode; without exit-node it creates a utun
// without owning the default route, so the higher-level check (is it on
// the *default* route?) correctly suppresses the warning there.
func isTUNInterface(iface string) bool {
	return tunInterfaceRe.MatchString(iface)
}

// tunProxyWarning returns the warning block for a TUN default route, or an
// empty string when the route is via a real interface (or absent). The
// caller decides whether to print a leading blank line.
func tunProxyWarning(iface string) string {
	if !isTUNInterface(iface) {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "WARNING: default route is via %s (likely sing-box / ClashX / V2Ray / Tailscale).\n", iface)
	b.WriteString("Outbound TCP bypasses egress-guard entirely. The daemon is enforcing nothing\n")
	b.WriteString("on this machine until the TUN proxy is stopped or reconfigured. See README\n")
	b.WriteString(`"Does it work with sing-box / ClashX / V2Ray" for details.`)
	b.WriteString("\n")
	return b.String()
}

// printPlatformStatus appends the LaunchAgent + LaunchDaemon + daemon lines
// beneath the kernel-rules line that Status() already printed, then a
// TUN-proxy warning block when applicable.
func printPlatformStatus(w io.Writer) error {
	r := Probe()
	if r.AgentLoaded {
		fmt.Fprintln(w, "LaunchAgent: ENABLED")
	} else {
		fmt.Fprintln(w, "LaunchAgent: NOT enabled (run `egress-guard enable`)")
	}
	switch {
	case r.DaemonPID > 0:
		fmt.Fprintf(w, "daemon: running (pid %d)\n", r.DaemonPID)
	case r.AgentLoaded:
		fmt.Fprintln(w, "daemon: not running (KeepAlive should restart it shortly)")
	default:
		fmt.Fprintln(w, "daemon: not running")
	}

	if r.BootDaemonLoaded {
		fmt.Fprintln(w, "LaunchDaemon (boot-resident): ENABLED")
	} else {
		fmt.Fprintln(w, "LaunchDaemon (boot-resident): NOT enabled (run `sudo egress-guard install`)")
	}
	switch {
	case r.BootDaemonPID > 0:
		fmt.Fprintf(w, "boot-daemon: running (pid %d)\n", r.BootDaemonPID)
	case r.BootDaemonLoaded:
		fmt.Fprintln(w, "boot-daemon: not running (KeepAlive should restart it shortly)")
	default:
		fmt.Fprintln(w, "boot-daemon: not running")
	}

	if warn := tunProxyWarning(r.TUNIface); warn != "" {
		fmt.Fprintln(w)
		fmt.Fprint(w, warn)
	}
	return nil
}
