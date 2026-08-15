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
	binary := filepath.Join(tempDir, "nebridge-proto")
	build := exec.Command("go", "build", "-o", binary, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build nebridge-proto: %v\n%s", err, output)
	}

	allowlistPath := filepath.Join(tempDir, "allowlist.toml")
	if err := os.WriteFile(allowlistPath, []byte("[allow]\nhosts = [\"good.example\"]\n"), 0o600); err != nil {
		t.Fatalf("write allowlist: %v", err)
	}

	socketPath := filepath.Join(tempDir, "nebridge.sock")
	command := exec.Command(binary,
		"-socket", socketPath,
		"-allowlist", allowlistPath,
		"-log", filepath.Join(tempDir, "decisions.log"),
		"-test-stub-identity",
	)
	if err := command.Start(); err != nil {
		t.Fatalf("start nebridge-proto: %v", err)
	}
	t.Cleanup(func() {
		if command.Process != nil {
			_ = command.Process.Kill()
		}
		_ = command.Wait()
	})

	waitForSocket(t, socketPath)

	if response := request(t, socketPath, "good.example"); response.Verdict != nebridge.VerdictAllow {
		t.Fatalf("good.example verdict = %v, want allow", response.Verdict)
	}
	if response := request(t, socketPath, "evil.example"); response.Verdict != nebridge.VerdictDrop {
		t.Fatalf("evil.example verdict = %v, want drop", response.Verdict)
	}
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
