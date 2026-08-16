package main

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/byliu-labs/egress-guard/internal/nebridge"
	"github.com/byliu-labs/egress-guard/internal/signature"
	"github.com/byliu-labs/egress-guard/internal/tlsparse"
)

func TestNebridgeProto_Smoke(t *testing.T) {
	tempDir := t.TempDir()
	binary := buildProto(t, tempDir)

	allowlistPath := filepath.Join(tempDir, "allowlist.toml")
	if err := os.WriteFile(allowlistPath, []byte("[allow]\nhosts = [\"bridge.localhost\"]\n"), 0o600); err != nil {
		t.Fatalf("write allowlist: %v", err)
	}

	socketPath := shortSocketPath(t)
	stderrPath := startProto(t, binary, socketPath, allowlistPath, filepath.Join(tempDir, "decisions.log"), filepath.Join(tempDir, "config"))

	waitForSocket(t, socketPath)
	waitForOutput(t, stderrPath, "nebridge: listening on "+socketPath)

	if response := request(t, socketPath, "bridge.localhost", "127.0.0.1"); response.Verdict != nebridge.VerdictAllow {
		t.Fatalf("bridge.localhost verdict = %v (%s), want allow", response.Verdict, response.Reason)
	}
	if response := request(t, socketPath, "evil.example", "127.0.0.1"); response.Verdict != nebridge.VerdictDrop {
		t.Fatalf("evil.example verdict = %v, want drop", response.Verdict)
	}
}

func TestNebridgeProto_BinderDropsMismatchAndDNSFailure(t *testing.T) {
	tempDir := t.TempDir()
	binary := buildProto(t, tempDir)
	allowlistPath := filepath.Join(tempDir, "allowlist.toml")
	if err := os.WriteFile(allowlistPath, []byte("[allow]\nhosts = [\"bridge.localhost\", \"no-such-host.invalid\"]\n"), 0o600); err != nil {
		t.Fatalf("write allowlist: %v", err)
	}

	socketPath := shortSocketPath(t)
	startProto(t, binary, socketPath, allowlistPath, filepath.Join(tempDir, "decisions.log"), filepath.Join(tempDir, "config"))
	waitForSocket(t, socketPath)

	response := request(t, socketPath, "bridge.localhost", "203.0.113.10")
	if response.Verdict != nebridge.VerdictDrop {
		t.Fatalf("bridge.localhost with mismatched destination verdict = %v, want drop", response.Verdict)
	}
	if response.Reason != "sni_ip_mismatch" {
		t.Fatalf("bridge.localhost with mismatched destination reason = %q, want sni_ip_mismatch", response.Reason)
	}
	response = request(t, socketPath, "no-such-host.invalid", "203.0.113.10")
	if response.Verdict != nebridge.VerdictDrop || response.Reason != "sni_ip_unverifiable" {
		t.Fatalf("unresolvable host response = %+v, want drop with sni_ip_unverifiable", response)
	}
}

func TestDefaultSocketPath_NonRootUsesStateDirectory(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("non-root default path is not used when running as root")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	defaultSocket, err := defaultSocketPath()
	if err != nil {
		t.Fatalf("defaultSocketPath: %v", err)
	}
	want := filepath.Join(home, ".local", "state", "egress-guard", defaultSocketName)
	if defaultSocket != want {
		t.Fatalf("default socket = %q, want %q", defaultSocket, want)
	}
}

func TestDefaultSocketPath_RootIsNotWorldWritable(t *testing.T) {
	defaultSocket, err := defaultSocketPath()
	if err != nil {
		t.Fatalf("defaultSocketPath: %v", err)
	}
	dir := filepath.Dir(defaultSocket)
	for {
		info, err := os.Stat(dir)
		if err == nil {
			if info.Mode().Perm()&0o002 != 0 {
				t.Fatalf("socket ancestor %s is world-writable (%v)", dir, info.Mode().Perm())
			}
			return
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("no existing ancestor of %s", defaultSocket)
		}
		dir = parent
	}
}

func TestNebridgeProto_DefaultSocketDirectoryCanBeCreatedPrivate(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	defaultSocket, err := defaultSocketPath()
	if err != nil {
		t.Fatalf("defaultSocketPath: %v", err)
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
host = "catalog.localhost"
`
	if err := os.WriteFile(filepath.Join(catalogDir, "catalog-baseline.toml"), []byte(catalogTOML), 0o600); err != nil {
		t.Fatalf("write baseline catalog: %v", err)
	}

	socketPath := shortSocketPath(t)
	startProto(t, binary, socketPath, allowlistPath, filepath.Join(tempDir, "decisions.log"), configHome)
	waitForSocket(t, socketPath)

	if response := request(t, socketPath, "catalog.localhost", "127.0.0.1"); response.Verdict != nebridge.VerdictAllow {
		t.Fatalf("catalog.localhost verdict = %v (%s), want allow", response.Verdict, response.Reason)
	}
}

func TestNebridgeProto_DefaultLogPath(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	path, err := defaultDecisionLogPath()
	if err != nil {
		t.Fatalf("defaultDecisionLogPath: %v", err)
	}
	want := filepath.Join(os.Getenv("HOME"), "Library", "Caches", "egress-guard", "nebridge-decisions.log")
	if path != want {
		t.Fatalf("default log path = %q, want %q", path, want)
	}
}

func TestNebridgeProto_OmittedLogUsesDefault(t *testing.T) {
	tempDir := t.TempDir()
	binary := buildProto(t, tempDir)
	allowlistPath := filepath.Join(tempDir, "allowlist.toml")
	if err := os.WriteFile(allowlistPath, []byte("[allow]\nhosts = [\"bridge.localhost\"]\n"), 0o600); err != nil {
		t.Fatalf("write allowlist: %v", err)
	}

	socketPath := shortSocketPath(t)
	startProto(t, binary, socketPath, allowlistPath, "", filepath.Join(tempDir, "config"))
	waitForSocket(t, socketPath)
	if response := request(t, socketPath, "bridge.localhost", "127.0.0.1"); response.Verdict != nebridge.VerdictAllow {
		t.Fatalf("bridge.localhost verdict = %v (%s), want allow", response.Verdict, response.Reason)
	}

	logPath := filepath.Join(tempDir, "Library", "Caches", "egress-guard", "nebridge-decisions.log")
	waitForFile(t, logPath)
}

func TestProductionIdentityResolverCachesSignatures(t *testing.T) {
	resolver, ok := productionIdentityResolver().(*nebridge.SystemResolver)
	if !ok {
		t.Fatalf("production resolver type = %T, want *nebridge.SystemResolver", productionIdentityResolver())
	}
	if _, ok := resolver.Sig.(*signature.CachingVerifier); !ok {
		t.Fatalf("production signature verifier type = %T, want *signature.CachingVerifier", resolver.Sig)
	}
}

func TestDefaultBuild_HasNoStubIdentityFlag(t *testing.T) {
	out, err := exec.Command("go", "build", "-o", filepath.Join(t.TempDir(), "nb"), ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(src), "test-stub-identity") {
		t.Fatal("main.go still registers -test-stub-identity in the default build; gate it behind //go:build nebridge_testing")
	}
}

func buildProto(t *testing.T, tempDir string) string {
	t.Helper()

	binary := filepath.Join(tempDir, "nebridge-proto")
	build := exec.Command("go", "build", "-tags", "nebridge_testing", "-o", binary, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build nebridge-proto: %v\n%s", err, output)
	}
	return binary
}

func startProto(t *testing.T, binary, socketPath, allowlistPath, logPath, configHome string) string {
	t.Helper()

	args := []string{
		"-socket", socketPath,
		"-allowlist", allowlistPath,
		"-test-stub-identity",
	}
	if logPath != "" {
		args = append(args, "-log", logPath)
	}
	command := exec.Command(binary, args...)
	stderr, err := os.CreateTemp(t.TempDir(), "stderr-")
	if err != nil {
		t.Fatalf("create stderr capture: %v", err)
	}
	command.Stderr = stderr
	if configHome != "" {
		command.Env = append(os.Environ(), "XDG_CONFIG_HOME="+configHome, "HOME="+filepath.Dir(configHome))
	}
	if err := command.Start(); err != nil {
		t.Fatalf("start nebridge-proto: %v", err)
	}
	t.Cleanup(func() {
		if command.Process != nil {
			_ = command.Process.Kill()
		}
		_ = command.Wait()
		_ = stderr.Close()
	})
	return stderr.Name()
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
	return dir
}

func waitForSocket(t *testing.T, socketPath string) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
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

func request(t *testing.T, socketPath, host, dstIP string) nebridge.Response {
	t.Helper()

	connection, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial nebridge-proto: %v", err)
	}
	defer connection.Close()

	err = nebridge.EncodeRequest(connection, nebridge.Request{
		DstIP:       net.ParseIP(dstIP),
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

func waitForOutput(t *testing.T, path, want string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		output, err := os.ReadFile(path)
		if err == nil && strings.Contains(string(output), want) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	output, _ := os.ReadFile(path)
	t.Fatalf("output %q does not contain %q", output, want)
}

func waitForFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if info, err := os.Stat(path); err == nil && info.Size() > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("file %s was not created with content", path)
}
