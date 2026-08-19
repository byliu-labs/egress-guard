//go:build darwin && integration

package integration

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

const bootDaemonLabel = "com.byliu.egress-guard.daemon"
const bootDaemonPlistPath = "/Library/LaunchDaemons/com.byliu.egress-guard.daemon.plist"
const bootDaemonLogPath = "/var/db/egress-guard/.local/state/egress-guard/blocked.log"

func requireBootE2E(t *testing.T) {
	t.Helper()
	skipIfNotRoot(t)
	if os.Getenv("EGRESS_GUARD_BOOT_E2E") != "1" {
		t.Skip("set EGRESS_GUARD_BOOT_E2E=1 as root after `sudo egress-guard install` to enable")
	}
}

// The boot daemon lives in the system domain, which `launchctl list <label>`
// cannot resolve — it queries the caller's user domain, and answers 113 there
// even under sudo. `launchctl print system/<label>` addresses it directly and
// prints a bare `pid = N` rather than the plist-style `"PID" = N;`. This is
// the same correction internal/cli got; leaving it here would mean the boot
// E2E could never observe the daemon it exists to test.
//
// UNVERIFIED as root: this environment has no TTY for sudo, and the whole file
// is gated behind skipIfNotRoot + EGRESS_GUARD_BOOT_E2E=1. The unprivileged
// half of the claim is covered by TestSystemDomainPrintAnswersUnprivileged.
var launchctlPIDRe = regexp.MustCompile(`(?m)^\s*(?:pid|"PID")\s*=\s*(\d+)\s*;?\s*$`)

func launchctlPID(label string) (int, bool) {
	out, err := exec.Command("launchctl", "print", "system/"+label).CombinedOutput()
	if err != nil {
		return 0, false
	}
	m := launchctlPIDRe.FindStringSubmatch(string(out))
	if m == nil {
		return 0, false
	}
	pid, err := strconv.Atoi(m[1])
	return pid, err == nil
}

func waitForPID(label string, deadline time.Duration) (int, error) {
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		if pid, ok := launchctlPID(label); ok && pid > 0 {
			return pid, nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return 0, fmt.Errorf("no PID for label %q after %v", label, deadline)
}

func TestBootDaemon_SimulatedRebootStartsBeforeUserSession(t *testing.T) {
	requireBootE2E(t)

	exec.Command("launchctl", "bootout", "system/"+bootDaemonLabel).Run()
	if out, err := exec.Command("launchctl", "bootstrap", "system", bootDaemonPlistPath).CombinedOutput(); err != nil {
		t.Fatalf("launchctl bootstrap: %v (output: %s)", err, out)
	}

	pid, err := waitForPID(bootDaemonLabel, 10*time.Second)
	if err != nil {
		t.Fatalf("daemon did not come up: %v", err)
	}
	if pid == 0 {
		t.Fatal("daemon PID is 0 after bootstrap")
	}
	if err := waitForPort(8443, 5*time.Second); err != nil {
		t.Fatalf("daemon not listening after bootstrap: %v", err)
	}
}

func TestBootDaemon_KilledProcessIsRestarted(t *testing.T) {
	requireBootE2E(t)

	before, err := waitForPID(bootDaemonLabel, 10*time.Second)
	if err != nil {
		t.Fatalf("daemon not running before kill test: %v", err)
	}
	if err := exec.Command("kill", "-9", strconv.Itoa(before)).Run(); err != nil {
		t.Fatalf("kill -9 %d: %v", before, err)
	}

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if after, ok := launchctlPID(bootDaemonLabel); ok && after > 0 && after != before {
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("daemon pid %d was not restarted within 15s of kill -9", before)
}

func TestBootDaemon_CronStyleFireProducesDecisionLogEntry(t *testing.T) {
	requireBootE2E(t)

	host := fmt.Sprintf("cron-sim-%d.example", time.Now().UnixNano())
	jobLabel := "com.egress-guard-test.cron-sim"
	exec.Command("launchctl", "bootout", "system/"+jobLabel).Run()

	out, err := exec.Command("launchctl", "submit", "-l", jobLabel, "--",
		"/usr/bin/curl", "-sS", "--max-time", "5", "https://"+host+"/").CombinedOutput()
	if err != nil {
		t.Fatalf("launchctl submit: %v (output: %s)", err, out)
	}
	defer exec.Command("launchctl", "bootout", "system/"+jobLabel).Run()

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		data, _ := os.ReadFile(bootDaemonLogPath)
		for _, line := range strings.Split(string(data), "\n") {
			if line == "" {
				continue
			}
			var e map[string]any
			if err := json.Unmarshal([]byte(line), &e); err != nil {
				continue
			}
			if e["host"] == host {
				return
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("no decision-log entry for host=%q within 15s", host)
}
