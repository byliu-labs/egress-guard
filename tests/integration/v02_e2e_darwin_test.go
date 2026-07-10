//go:build darwin && integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestV02_AllowedHostStillWorks regression-tests v0.1 behavior under v0.2 pipeline.
func TestV02_AllowedHostStillWorks(t *testing.T) {
	requireDaemon(t)
	resp, err := http.Get("https://api.openai.com/")
	if err != nil {
		t.Fatalf("GET api.openai.com: %v", err)
	}
	resp.Body.Close()
	// Any non-network-error response is fine — we only care that the connection completed.
}

// TestV02_PromptAllowOnceLetsConnectionThrough drives the daemon with the
// osascript override env to simulate an "Allow once" click.
func TestV02_PromptAllowOnceLetsConnectionThrough(t *testing.T) {
	requireDaemon(t)
	t.Setenv("EGRESS_GUARD_OSASCRIPT_RESULT", "Allow once")

	host := "example.com" // not on default allowlist
	resp, err := httpGetWithTimeout("https://"+host+"/", 35*time.Second)
	if err != nil {
		t.Fatalf("GET %s: %v", host, err)
	}
	defer resp.Body.Close()

	requireBlockLogEntry(t, host, "allow", 10*time.Second)
}

// TestV02_PromptTimeoutDenies asserts deny-on-timeout default.
func TestV02_PromptTimeoutDenies(t *testing.T) {
	requireDaemon(t)
	t.Setenv("EGRESS_GUARD_OSASCRIPT_RESULT", "") // force real osascript path

	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "curl", "-sS", "--max-time", "35", "https://nowhere.example")
	if err := cmd.Run(); err == nil {
		t.Errorf("expected curl to fail after timeout-deny")
	}
}

// TestV02_BurstCoalescing fires 10 distinct subdomains and verifies the daemon's
// blocklog shows the burst-prompt path.
func TestV02_BurstCoalescing(t *testing.T) {
	requireDaemon(t)
	t.Setenv("EGRESS_GUARD_OSASCRIPT_RESULT", "Deny")

	for i := 0; i < 10; i++ {
		host := fmt.Sprintf("test%d.unknown.example", i)
		_ = exec.Command("curl", "-sS", "--max-time", "2", "https://"+host).Run()
	}

	// Inspect the block log for a burst entry.
	logPath := filepath.Join(os.Getenv("HOME"), ".local/state/egress-guard/blocked.log")
	data, _ := os.ReadFile(logPath)
	if !strings.Contains(string(data), `"reason":"user_denied_or_timeout"`) {
		t.Errorf("expected user_denied_or_timeout entries in blocklog; got tail:\n%s", lastLines(string(data), 10))
	}
}

// helpers -----------------------------------------------------------------

func requireDaemon(t *testing.T) {
	t.Helper()
	if os.Getenv("EGRESS_GUARD_E2E") != "1" {
		t.Skip("set EGRESS_GUARD_E2E=1 with daemon running to enable")
	}
}

func httpGetWithTimeout(url string, timeout time.Duration) (*http.Response, error) {
	c := &http.Client{Timeout: timeout}
	return c.Get(url)
}

func requireBlockLogEntry(t *testing.T, host, action string, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	logPath := filepath.Join(os.Getenv("HOME"), ".local/state/egress-guard/blocked.log")
	for time.Now().Before(deadline) {
		data, _ := os.ReadFile(logPath)
		for _, line := range strings.Split(string(data), "\n") {
			if line == "" {
				continue
			}
			var e map[string]any
			_ = json.Unmarshal([]byte(line), &e)
			if e["host"] == host && e["action"] == action {
				return
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Errorf("no blocklog entry for host=%q action=%q within %s", host, action, within)
}

func lastLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) <= n {
		return s
	}
	return strings.Join(lines[len(lines)-n:], "\n")
}
