package nebridge

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/byliu-labs/egress-guard/internal/allowlist"
	"github.com/byliu-labs/egress-guard/internal/daemon"
	"github.com/byliu-labs/egress-guard/internal/decisionlog"
	"github.com/byliu-labs/egress-guard/internal/kernel"
)

func TestServer_AllowlistedHostAllows(t *testing.T) {
	server := newTestServer(t, false, StubResolver{})

	response := server.request(t, "allow.example", nil)

	if response.Verdict != VerdictAllow {
		t.Fatalf("Verdict = %v, want allow", response.Verdict)
	}
	entry := server.onlyLogEntry(t)
	if entry.Decision != decisionlog.DecisionAllow {
		t.Fatalf("logged decision = %q, want allow", entry.Decision)
	}
	if entry.DestIP != "203.0.113.10" || entry.DestPort != 443 {
		t.Fatalf("logged destination = %s:%d, want 203.0.113.10:443", entry.DestIP, entry.DestPort)
	}
}

func TestServer_UnknownHostDrops(t *testing.T) {
	server := newTestServer(t, false, StubResolver{})

	response := server.request(t, "unknown.example", nil)

	if response.Verdict != VerdictDrop {
		t.Fatalf("Verdict = %v, want drop", response.Verdict)
	}
	if entry := server.onlyLogEntry(t); entry.Decision != decisionlog.DecisionDeny {
		t.Fatalf("logged decision = %q, want deny", entry.Decision)
	}
}

func TestServer_ObserveMode_AllowsButLogsObserve(t *testing.T) {
	server := newTestServer(t, true, StubResolver{})

	response := server.request(t, "unknown.example", nil)

	if response.Verdict != VerdictAllow {
		t.Fatalf("Verdict = %v, want allow", response.Verdict)
	}
	if entry := server.onlyLogEntry(t); entry.Decision != decisionlog.DecisionObserve {
		t.Fatalf("logged decision = %q, want observe", entry.Decision)
	}
}

func TestServer_MalformedClientHelloDrops(t *testing.T) {
	server := newTestServer(t, false, StubResolver{})

	response := server.request(t, "", []byte{0xff, 0x00, 0x01})

	if response.Verdict != VerdictDrop {
		t.Fatalf("Verdict = %v, want drop", response.Verdict)
	}
	if !strings.HasPrefix(response.Reason, "sni_parse_failed:") {
		t.Fatalf("Reason = %q, want sni_parse_failed prefix", response.Reason)
	}
	if entry := server.onlyLogEntry(t); entry.Decision != decisionlog.DecisionDeny {
		t.Fatalf("logged decision = %q, want deny", entry.Decision)
	}
}

func TestServer_ResolverErrorDrops(t *testing.T) {
	server := newTestServer(t, false, StubResolver{Err: errors.New("resolver unavailable")})

	response := server.request(t, "allow.example", nil)

	if response.Verdict != VerdictDrop {
		t.Fatalf("Verdict = %v, want drop", response.Verdict)
	}
	if !strings.HasPrefix(response.Reason, "identity_resolve_failed:") {
		t.Fatalf("Reason = %q, want identity_resolve_failed prefix", response.Reason)
	}
	if entry := server.onlyLogEntry(t); entry.Decision != decisionlog.DecisionDeny {
		t.Fatalf("logged decision = %q, want deny", entry.Decision)
	}
}

func TestListen_PreservesExistingDirectoryPermissions(t *testing.T) {
	parent, err := os.MkdirTemp("", "nb-")
	if err != nil {
		t.Fatalf("create short socket parent: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(parent); err != nil {
			t.Errorf("remove socket parent: %v", err)
		}
	})
	dir := filepath.Join(parent, "shared")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatalf("create shared directory: %v", err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatalf("set shared directory permissions: %v", err)
	}

	listener, err := Listen(filepath.Join(dir, "s"))
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat shared directory: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o755 {
		t.Fatalf("shared directory mode = %o, want 755", mode)
	}
	socketInfo, err := os.Stat(filepath.Join(dir, "s"))
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if mode := socketInfo.Mode().Perm(); mode != 0o600 {
		t.Fatalf("socket mode = %o, want 600", mode)
	}
}

type testServer struct {
	path    string
	logPath string
}

func newTestServer(tb testing.TB, observeOnly bool, resolver IdentityResolver) testServer {
	tb.Helper()

	logPath := filepath.Join(tb.TempDir(), "decisions.log")
	log, err := decisionlog.Open(logPath)
	if err != nil {
		tb.Fatalf("open decision log: %v", err)
	}
	tb.Cleanup(func() { _ = log.Close() })

	decider, err := daemon.New(daemon.Options{
		Listen: "127.0.0.1:0",
		Kernel: kernel.Default(),
		Allow: allowlist.New(allowlist.Config{
			Defaults: allowlist.Layer{Allow: []string{"allow.example"}},
		}),
		Log:         log,
		ObserveOnly: observeOnly,
	})
	if err != nil {
		tb.Fatalf("new daemon: %v", err)
	}

	path := testSocketPath(tb)
	ln, err := Listen(path)
	if err != nil {
		tb.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- (&Server{Decider: decider, Resolver: resolver, Log: log}).Serve(ctx, ln) }()
	tb.Cleanup(func() {
		cancel()
		_ = ln.Close()
		if err := <-serveDone; err != nil {
			tb.Errorf("Serve: %v", err)
		}
	})

	return testServer{path: path, logPath: logPath}
}

func testSocketPath(tb testing.TB) string {
	tb.Helper()

	socketDir := tb.TempDir()
	shortParent, err := os.MkdirTemp("", "nebridge-")
	if err != nil {
		tb.Fatalf("make short socket path: %v", err)
	}
	tb.Cleanup(func() {
		if err := os.RemoveAll(shortParent); err != nil {
			tb.Errorf("remove short socket path: %v", err)
		}
	})

	shortSocketDir := filepath.Join(shortParent, "d")
	if err := os.Symlink(socketDir, shortSocketDir); err != nil {
		tb.Fatalf("link short socket path: %v", err)
	}
	return filepath.Join(shortSocketDir, "s")
}

func (s testServer) request(t *testing.T, host string, clientHello []byte) Response {
	t.Helper()
	if clientHello == nil {
		clientHello = clientHelloForHost(host)
	}

	conn, err := net.Dial("unix", s.path)
	if err != nil {
		t.Fatalf("dial server: %v", err)
	}
	defer conn.Close()

	request := Request{
		DstIP:       net.ParseIP("203.0.113.10"),
		DstPort:     443,
		AuditToken:  [32]byte{1},
		ClientHello: clientHello,
	}
	if err := EncodeRequest(conn, request); err != nil {
		t.Fatalf("encode request: %v", err)
	}
	response, err := DecodeResponse(conn)
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return response
}

func (s testServer) onlyLogEntry(t *testing.T) decisionlog.Entry {
	t.Helper()
	entries, err := decisionlog.Read(s.logPath)
	if err != nil {
		t.Fatalf("read decision log: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("log entries = %d, want 1", len(entries))
	}
	return entries[0]
}

func clientHelloForHost(host string) []byte {
	body := make([]byte, 0, 128)
	body = append(body, 0x03, 0x03)
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00)
	body = append(body, 0x00, 0x02, 0x13, 0x01)
	body = append(body, 0x01, 0x00)

	sni := append([]byte{0x00, byte(len(host) >> 8), byte(len(host))}, host...)
	sni = append([]byte{byte(len(sni) >> 8), byte(len(sni))}, sni...)
	extensions := append([]byte{0x00, 0x00, byte(len(sni) >> 8), byte(len(sni))}, sni...)
	body = append(body, byte(len(extensions)>>8), byte(len(extensions)))
	body = append(body, extensions...)

	handshake := append([]byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	return append([]byte{0x16, 0x03, 0x01, byte(len(handshake) >> 8), byte(len(handshake))}, handshake...)
}
