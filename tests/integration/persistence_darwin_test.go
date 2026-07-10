//go:build darwin && integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type decisionEntry struct {
	Host        string `json:"host"`
	Action      string `json:"action"`
	Persistence *struct {
		Kind      string `json:"kind"`
		Label     string `json:"label"`
		FirstSeen string `json:"first_seen"`
		New       bool   `json:"new"`
	} `json:"persistence"`
}

func startDaemon(t *testing.T) (stateHome string, cleanup func()) {
	t.Helper()
	skipIfNotRoot(t)
	skipIfBinaryMissing(t)

	stateHome = t.TempDir()
	t.Setenv("XDG_STATE_HOME", stateHome)

	mustRun(t, binaryPath(t), "install")

	ctx, cancel := context.WithCancel(context.Background())
	daemon := exec.CommandContext(ctx, binaryPath(t), "start")
	daemon.Env = append(os.Environ(), "XDG_STATE_HOME="+stateHome)
	if err := daemon.Start(); err != nil {
		cancel()
		t.Fatalf("daemon start: %v", err)
	}
	if err := waitForPort(8443, 5*time.Second); err != nil {
		cancel()
		_ = daemon.Wait()
		t.Fatalf("daemon not listening: %v", err)
	}

	return stateHome, func() {
		cancel()
		_ = daemon.Wait()
		_ = exec.Command(binaryPath(t), "uninstall").Run()
	}
}

func waitForDecisionEntry(t *testing.T, stateHome, host string, within time.Duration) decisionEntry {
	t.Helper()
	logPath := filepath.Join(stateHome, "egress-guard", "blocked.log")
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		data, _ := os.ReadFile(logPath)
		for _, line := range strings.Split(string(data), "\n") {
			if line == "" {
				continue
			}
			var e decisionEntry
			if err := json.Unmarshal([]byte(line), &e); err != nil {
				continue
			}
			if e.Host == host {
				return e
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("no decision-log entry for host=%q within %s", host, within)
	return decisionEntry{}
}

func TestE2E_LaunchAgentEgressAttributedToLaunchd(t *testing.T) {
	stateHome, cleanup := startDaemon(t)
	defer cleanup()

	const label = "com.egressguard.test.launchdbeacon"
	const host = "github.com"
	plistPath := filepath.Join("/Library/LaunchDaemons", label+".plist")
	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key><string>%s</string>
	<key>ProgramArguments</key>
	<array>
		<string>/usr/bin/curl</string>
		<string>-sS</string>
		<string>--max-time</string>
		<string>10</string>
		<string>https://%s/</string>
	</array>
	<key>RunAtLoad</key><true/>
</dict>
</plist>
`, label, host)
	if err := os.WriteFile(plistPath, []byte(plist), 0o644); err != nil {
		t.Fatalf("write plist: %v", err)
	}
	t.Cleanup(func() {
		_ = exec.Command("launchctl", "bootout", "system/"+label).Run()
		_ = os.Remove(plistPath)
	})

	mustRun(t, "launchctl", "bootstrap", "system", plistPath)

	entry := waitForDecisionEntry(t, stateHome, host, 15*time.Second)
	if entry.Persistence == nil {
		t.Fatal("expected Persistence to be populated")
	}
	if entry.Persistence.Kind != "launchd" {
		t.Errorf("Kind = %q, want %q", entry.Persistence.Kind, "launchd")
	}
	if entry.Persistence.Label != label {
		t.Errorf("Label = %q, want %q", entry.Persistence.Label, label)
	}
	if entry.Persistence.FirstSeen == "" {
		t.Error("FirstSeen is empty")
	}
	if !entry.Persistence.New {
		t.Error("New = false, want true (fresh ledger)")
	}
}

func TestE2E_CronEgressAttributedToCron(t *testing.T) {
	stateHome, cleanup := startDaemon(t)
	defer cleanup()

	const host = "api.github.com"
	next := time.Now().Add(70 * time.Second)
	cronLine := fmt.Sprintf("%d %d * * * /usr/bin/curl -sS --max-time 10 https://%s/\n",
		next.Minute(), next.Hour(), host)

	existing, _ := exec.Command("crontab", "-l").Output()
	newCrontab := string(existing) + cronLine
	installCmd := exec.Command("crontab", "-")
	installCmd.Stdin = strings.NewReader(newCrontab)
	if err := installCmd.Run(); err != nil {
		t.Fatalf("install crontab: %v", err)
	}
	t.Cleanup(func() {
		restore := exec.Command("crontab", "-")
		restore.Stdin = strings.NewReader(string(existing))
		_ = restore.Run()
	})

	entry := waitForDecisionEntry(t, stateHome, host, 100*time.Second)
	if entry.Persistence == nil {
		t.Fatal("expected Persistence to be populated")
	}
	if entry.Persistence.Kind != "cron" {
		t.Errorf("Kind = %q, want %q", entry.Persistence.Kind, "cron")
	}
	if entry.Persistence.FirstSeen == "" {
		t.Error("FirstSeen is empty")
	}
	if !entry.Persistence.New {
		t.Error("New = false, want true (fresh ledger)")
	}
}

func TestE2E_InteractiveCurlNotFlaggedAsNewPersistence(t *testing.T) {
	stateHome, cleanup := startDaemon(t)
	defer cleanup()

	const host = "api.anthropic.com"
	cmd := exec.Command("curl", "-sS", "--max-time", "10", "https://"+host+"/")
	if err := cmd.Run(); err != nil {
		t.Fatalf("curl: %v", err)
	}

	entry := waitForDecisionEntry(t, stateHome, host, 10*time.Second)
	if entry.Persistence == nil {
		t.Fatal("expected Persistence to be populated")
	}
	for _, bad := range []string{"launchd", "cron", "rc_hook"} {
		if entry.Persistence.Kind == bad {
			t.Errorf("Kind = %q: directly-run curl must not be attributed to persistence", bad)
		}
	}
	if entry.Persistence.New {
		t.Error("New = true: interactive/non-persistent source must never report New")
	}
}
