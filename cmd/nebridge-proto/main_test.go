package main

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/byliu-labs/egress-guard/internal/nebridge"
	"github.com/byliu-labs/egress-guard/internal/tlsparse"
)

func TestNebridgeProto_Smoke(t *testing.T) {
	tempDir := t.TempDir()
	binary := buildProto(t, tempDir)

	allowlistPath := filepath.Join(tempDir, "allowlist.toml")
	if err := os.WriteFile(allowlistPath, []byte("[allow]\nhosts = [\"good.example\"]\n"), 0o600); err != nil {
		t.Fatalf("write allowlist: %v", err)
	}

	socketPath := shortSocketPath(t)
	startProto(t, binary, socketPath, allowlistPath, filepath.Join(tempDir, "decisions.log"), "")

	waitForSocket(t, socketPath)

	if response := request(t, socketPath, "good.example"); response.Verdict != nebridge.VerdictAllow {
		t.Fatalf("good.example verdict = %v, want allow", response.Verdict)
	}
	if response := request(t, socketPath, "evil.example"); response.Verdict != nebridge.VerdictDrop {
		t.Fatalf("evil.example verdict = %v, want drop", response.Verdict)
	}
}

func TestNebridgeProto_DefaultSocketUsesPrivateDirectory(t *testing.T) {
	if filepath.Dir(defaultSocket) == "/tmp" {
		t.Fatalf("default socket %q is directly in shared temporary directory /tmp", defaultSocket)
	}
	root := shortSocketDir(t)
	socketPath := filepath.Join(root, filepath.Base(filepath.Dir(defaultSocket)), filepath.Base(defaultSocket))
	listener, err := nebridge.Listen(socketPath)
	if err != nil {
		t.Fatalf("listen using default directory layout: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	info, err := os.Stat(filepath.Dir(socketPath))
	if err != nil {
		t.Fatalf("stat default socket directory: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o700 {
		t.Fatalf("default socket directory mode = %o, want 700", mode)
	}
}

func TestNebridgeProto_UsesBaselineCatalog(t *testing.T) {
	tempDir := t.TempDir()
	binary := buildProto(t, tempDir)
	allowlistPath := filepath.Join(tempDir, "allowlist.toml")
	if err := os.WriteFile(allowlistPath, []byte("[allow]\nhosts = []\n"), 0o600); err != nil {
		t.Fatalf("write allowlist: %v", err)
	}

	configHome := filepath.Join(tempDir, "config")
	catalogDir := filepath.Join(configHome, "egress-guard")
	if err := os.MkdirAll(catalogDir, 0o700); err != nil {
		t.Fatalf("create catalog directory: %v", err)
	}
	catalogTOML := `[[entry]]
schema_version = 1
layer = "baseline"
confidence = "medium"
evidence = "test fixture"
explanation = "test fixture"

[entry.identity]
exe_basename = "nebridge-proto-test"

[[entry.expected_destinations]]
host = "catalog.example"
`
	if err := os.WriteFile(filepath.Join(catalogDir, "catalog-baseline.toml"), []byte(catalogTOML), 0o600); err != nil {
		t.Fatalf("write baseline catalog: %v", err)
	}

	socketPath := shortSocketPath(t)
	startProto(t, binary, socketPath, allowlistPath, filepath.Join(tempDir, "decisions.log"), configHome)
	waitForSocket(t, socketPath)

	if response := request(t, socketPath, "catalog.example"); response.Verdict != nebridge.VerdictAllow {
		t.Fatalf("catalog.example verdict = %v, want allow", response.Verdict)
	}
}

func buildProto(t *testing.T, tempDir string) string {
	t.Helper()

	binary := filepath.Join(tempDir, "nebridge-proto")
	build := exec.Command("go", "build", "-o", binary, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build nebridge-proto: %v\n%s", err, output)
	}
	return binary
}

func startProto(t *testing.T, binary, socketPath, allowlistPath, logPath, configHome string) {
	t.Helper()

	command := exec.Command(binary,
		"-socket", socketPath,
		"-allowlist", allowlistPath,
		"-log", logPath,
		"-test-stub-identity",
	)
	if configHome != "" {
		command.Env = append(os.Environ(), "XDG_CONFIG_HOME="+configHome)
	}
	if err := command.Start(); err != nil {
		t.Fatalf("start nebridge-proto: %v", err)
	}
	t.Cleanup(func() {
		if command.Process != nil {
			_ = command.Process.Kill()
		}
		_ = command.Wait()
	})
}

func shortSocketPath(t *testing.T) string {
	t.Helper()

	return filepath.Join(shortSocketDir(t), "s")
}

func shortSocketDir(t *testing.T) string {
	t.Helper()

	dir, err := os.MkdirTemp("", "nb-")
	if err != nil {
		t.Fatalf("create socket directory: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("remove socket directory: %v", err)
		}
	})
	return filepath.Join(dir, "s")
}

func waitForSocket(t *testing.T, socketPath string) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		connection, err := net.DialTimeout("unix", socketPath, 50*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("nebridge-proto did not listen on %s", socketPath)
}

func request(t *testing.T, socketPath, host string) nebridge.Response {
	t.Helper()

	connection, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial nebridge-proto: %v", err)
	}
	defer connection.Close()

	err = nebridge.EncodeRequest(connection, nebridge.Request{
		DstIP:       net.ParseIP("203.0.113.10"),
		DstPort:     443,
		AuditToken:  [32]byte{1},
		ClientHello: tlsparse.BuildClientHelloForTest(host, true),
	})
	if err != nil {
		t.Fatalf("encode %s request: %v", host, err)
	}
	response, err := nebridge.DecodeResponse(connection)
	if err != nil {
		t.Fatalf("decode %s response: %v", host, err)
	}
	return response
}
