//go:build darwin && integration

package integration

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestE2E_AllowedHostSucceeds runs the full pipeline:
//  1. sudo bin/egress-guard install
//  2. bin/egress-guard start &
//  3. curl https://github.com/  (should succeed - any 2xx/3xx response means TLS got through)
//  4. curl https://nonexistent.example.invalid/  (should fail with conn refused / RST)
//  5. tail block log; expect a deny entry
//  6. sudo bin/egress-guard uninstall
//
// Prereqs:
//   - run from repo root
//   - `make build` has produced bin/egress-guard
//   - sudo without password configured for pfctl, or interactive
//
// Run:
//
//	sudo go test -tags=integration -v -timeout=120s ./tests/integration/
func TestE2E_AllowedHostSucceeds(t *testing.T) {
	skipIfNotRoot(t)
	skipIfBinaryMissing(t)

	mustRun(t, binaryPath(t), "install")
	t.Cleanup(func() { _ = exec.Command(binaryPath(t), "uninstall").Run() })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	daemon := exec.CommandContext(ctx, binaryPath(t), "start")
	if err := daemon.Start(); err != nil {
		t.Fatalf("daemon start: %v", err)
	}
	t.Cleanup(func() { cancel(); _ = daemon.Wait() })

	if err := waitForPort(8443, 5*time.Second); err != nil {
		t.Fatalf("daemon not listening: %v", err)
	}

	// Allowed host - expect TLS to succeed (any 2xx/3xx response means TLS got through)
	out, err := exec.Command("curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
		"--max-time", "10", "https://github.com/").CombinedOutput()
	if err != nil {
		t.Errorf("curl allowed host failed: %v: %s", err, out)
	} else {
		code := string(out)
		if !strings.HasPrefix(code, "2") && !strings.HasPrefix(code, "3") {
			t.Errorf("curl allowed: unexpected status %s (expected 2xx/3xx)", code)
		}
	}

	// Denied host - expect curl to error (connection failed)
	out, err = exec.Command("curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
		"--max-time", "5", "https://nonexistent.example.invalid/").CombinedOutput()
	if err == nil {
		t.Errorf("curl denied: expected error, got status %s", out)
	}

	// The block log should contain a deny entry. Allow time for the log to flush.
	time.Sleep(500 * time.Millisecond)
	logPath := filepath.Join(stateDir(t), "blocked.log")
	contents := mustReadFile(t, logPath)
	if !strings.Contains(contents, `"action":"deny"`) {
		t.Errorf("expected deny entry in block log; got:\n%s", contents)
	}
}
