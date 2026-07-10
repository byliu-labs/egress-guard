//go:build integration

package integration

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func skipIfNotRoot(t *testing.T) {
	t.Helper()
	out, _ := exec.Command("id", "-u").Output()
	if strings.TrimSpace(string(out)) != "0" {
		t.Skip("integration test requires sudo")
	}
}

// binaryPath returns the absolute path to the project's egress-guard binary.
// Walks up from the test source file to find the repo root (the directory
// containing go.mod), then appends bin/egress-guard. Resolved at call-time so
// `go test ./tests/integration/` and `go test ./...` both work.
func binaryPath(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(filename)
	for i := 0; i < 6; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return filepath.Join(dir, "bin", "egress-guard")
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("could not locate repo root from test source")
	return ""
}

func skipIfBinaryMissing(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(binaryPath(t)); err != nil {
		t.Skip("egress-guard binary not built — run `make build` from repo root first")
	}
}

func mustRun(t *testing.T, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
}

func waitForPort(port int, deadline time.Duration) error {
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			c.Close()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("port %d not open after %v", port, deadline)
}

func stateDir(t *testing.T) string {
	t.Helper()
	if x := os.Getenv("XDG_STATE_HOME"); x != "" {
		return filepath.Join(x, "egress-guard")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "state", "egress-guard")
}

func mustReadFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	return string(b)
}
