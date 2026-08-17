package nebridge

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/byliu-labs/egress-guard/internal/allowlist"
	"github.com/byliu-labs/egress-guard/internal/daemon"
	"github.com/byliu-labs/egress-guard/internal/decisionlog"
	"github.com/byliu-labs/egress-guard/internal/kernel"
	"github.com/byliu-labs/egress-guard/internal/procid"
	"github.com/byliu-labs/egress-guard/internal/signature"
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

func TestServer_InvalidDecisionFailsClosed(t *testing.T) {
	server := newTestServerWithDecider(t, entryDecider{
		entry: decisionlog.Entry{Decision: "", Action: ""},
	}, StubResolver{})

	response := server.request(t, "allow.example", nil)

	if response.Verdict != VerdictDrop {
		t.Fatalf("Verdict = %v, want drop", response.Verdict)
	}
	if response.Reason != "invalid_decision: empty" {
		t.Fatalf("Reason = %q, want invalid_decision: empty", response.Reason)
	}
	entry := server.onlyLogEntry(t)
	if entry.Decision != decisionlog.DecisionDeny || entry.Action != string(decisionlog.DecisionDeny) {
		t.Fatalf("logged decision/action = %q/%q, want deny/deny", entry.Decision, entry.Action)
	}
}

func TestServer_UnknownDecisionFailsClosed(t *testing.T) {
	server := newTestServerWithDecider(t, entryDecider{
		entry: decisionlog.Entry{Decision: decisionlog.Decision("future")},
	}, StubResolver{})

	response := server.request(t, "allow.example", nil)

	if response.Verdict != VerdictDrop {
		t.Fatalf("Verdict = %v, want drop", response.Verdict)
	}
	if response.Reason != `invalid_decision: "future"` {
		t.Fatalf("Reason = %q, want invalid future decision", response.Reason)
	}
}

func TestServer_MalformedRequestIsLogged(t *testing.T) {
	server := newTestServer(t, false, StubResolver{})
	connection, err := net.Dial("unix", server.path)
	if err != nil {
		t.Fatalf("dial server: %v", err)
	}
	if _, err := connection.Write(malformedRequestFrame(t)); err != nil {
		t.Fatalf("write malformed request: %v", err)
	}

	response, err := DecodeResponse(connection)
	if err != nil {
		t.Fatalf("decode malformed response: %v", err)
	}
	if response.Verdict != VerdictDrop {
		t.Fatalf("Verdict = %v, want drop", response.Verdict)
	}
	if !strings.HasPrefix(response.Reason, "frame_decode_failed:") {
		t.Fatalf("Reason = %q, want frame_decode_failed prefix", response.Reason)
	}
	_ = connection.Close()

	entry := server.waitForOnlyLogEntry(t)
	if entry.Decision != decisionlog.DecisionDeny {
		t.Fatalf("logged decision = %q, want deny", entry.Decision)
	}
	if !strings.HasPrefix(entry.Reason, "frame_decode_failed:") {
		t.Fatalf("Reason = %q, want frame_decode_failed prefix", entry.Reason)
	}
}

func TestServer_IdleRequestDeadlineLogsDeny(t *testing.T) {
	server := newTestServerWithBinderAndDeadline(t, false, StubResolver{}, nil, 20*time.Millisecond)
	connection, err := net.Dial("unix", server.path)
	if err != nil {
		t.Fatalf("dial server: %v", err)
	}
	defer connection.Close()

	entry := server.waitForOnlyLogEntry(t)
	if entry.Decision != decisionlog.DecisionDeny {
		t.Fatalf("logged decision = %q, want deny", entry.Decision)
	}
	if !strings.HasPrefix(entry.Reason, "idle_request_timeout:") {
		t.Fatalf("Reason = %q, want idle_request_timeout prefix", entry.Reason)
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

func TestServer_SNIDestinationMismatchDrops(t *testing.T) {
	server := newTestServerWithBinder(t, false, StubResolver{}, stubBinder{matches: false})

	response := server.request(t, "allow.example", nil)

	if response.Verdict != VerdictDrop || response.Reason != "sni_ip_mismatch" {
		t.Fatalf("response = %+v, want drop with sni_ip_mismatch", response)
	}
}

func TestServer_DNSFailureDrops(t *testing.T) {
	server := newTestServerWithBinder(t, false, StubResolver{}, stubBinder{err: errors.New("resolver unavailable")})

	response := server.request(t, "allow.example", nil)

	if response.Verdict != VerdictDrop || response.Reason != "sni_ip_unverifiable" {
		t.Fatalf("response = %+v, want drop with sni_ip_unverifiable", response)
	}
}

type stubBinder struct {
	matches bool
	err     error
}

func (b stubBinder) DestMatches(string, net.IP) (bool, error) {
	return b.matches, b.err
}

func TestListen_RejectsUnsafeExistingDirectoryPermissions(t *testing.T) {
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

	_, err = Listen(filepath.Join(dir, "s"))
	if err == nil || !strings.Contains(err.Error(), "mode 755, want 700") {
		t.Fatalf("Listen error = %v, want unsafe mode rejection", err)
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat shared directory: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o755 {
		t.Fatalf("shared directory mode = %o, want 755", mode)
	}
	if _, err := os.Lstat(filepath.Join(dir, "s")); !os.IsNotExist(err) {
		t.Fatalf("unsafe directory socket path error = %v, want not exist", err)
	}
}

func TestListen_CreatesPrivateDirectoryAndSocket(t *testing.T) {
	parent, err := os.MkdirTemp("", "nb-")
	if err != nil {
		t.Fatalf("create short socket parent: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(parent) })
	dir := filepath.Join(parent, "socket-dir")
	socketPath := filepath.Join(dir, "s")

	listener, err := Listen(socketPath)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat socket directory: %v", err)
	}
	if mode := dirInfo.Mode().Perm(); mode != 0o700 {
		t.Fatalf("socket directory mode = %o, want 700", mode)
	}
	socketInfo, err := os.Stat(socketPath)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if mode := socketInfo.Mode().Perm(); mode != 0o600 {
		t.Fatalf("socket mode = %o, want 600", mode)
	}
}

func TestListen_RejectsSymlinkedSocketDirectory(t *testing.T) {
	parent, err := os.MkdirTemp("", "nb-")
	if err != nil {
		t.Fatalf("create short socket parent: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(parent) })
	target := filepath.Join(parent, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatalf("create target directory: %v", err)
	}
	link := filepath.Join(parent, "socket-dir")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("create socket directory symlink: %v", err)
	}

	_, err = Listen(filepath.Join(link, "s"))
	if err == nil || !strings.Contains(err.Error(), "is a symlink") {
		t.Fatalf("Listen error = %v, want symlink rejection", err)
	}
	if _, err := os.Lstat(filepath.Join(target, "s")); !os.IsNotExist(err) {
		t.Fatalf("symlink target socket path error = %v, want not exist", err)
	}
}

func TestValidateSocketDirectory_RejectsWrongOwner(t *testing.T) {
	info := fakeFileInfo{mode: os.ModeDir | 0o700, uid: uint32(os.Geteuid() + 1)}
	err := validateSocketDirectory("/tmp/unsafe", info)
	if err == nil || !strings.Contains(err.Error(), "is owned by euid") {
		t.Fatalf("validateSocketDirectory error = %v, want owner rejection", err)
	}
}

func TestServer_CancelClosesActiveConnectionAndReturns(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "decisions.log")
	log, err := decisionlog.Open(logPath)
	if err != nil {
		t.Fatalf("open decision log: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })

	decider, err := daemon.New(daemon.Options{
		Listen: "127.0.0.1:0",
		Kernel: kernel.Default(),
		Allow: allowlist.New(allowlist.Config{
			Defaults: allowlist.Layer{Allow: []string{"allow.example"}},
		}),
		Log: log,
	})
	if err != nil {
		t.Fatalf("new daemon: %v", err)
	}
	path := testSocketPath(t)
	ln, err := Listen(path)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- (&Server{Decider: decider, Resolver: StubResolver{}, Log: log}).Serve(ctx, ln)
	}()

	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dial server: %v", err)
	}
	defer conn.Close()
	stop := make(chan struct{})
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if err := EncodeRequest(conn, Request{
				DstIP:       net.ParseIP("203.0.113.10"),
				DstPort:     443,
				AuditToken:  [32]byte{1},
				ClientHello: clientHelloForHost("allow.example"),
			}); err != nil {
				return
			}
			if _, err := DecodeResponse(conn); err != nil {
				return
			}
		}
	}()

	cancel()
	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatalf("Serve: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		close(stop)
		_ = conn.Close()
		_ = ln.Close()
		<-writerDone
		if err := <-serveDone; err != nil {
			t.Logf("Serve after forced cleanup: %v", err)
		}
		t.Fatal("Serve did not return after cancellation while an active client kept sending requests")
	}
	close(stop)
	<-writerDone
}

func TestServer_ResponseWriteFailureClosesStream(t *testing.T) {
	var request bytes.Buffer
	if err := EncodeRequest(&request, Request{
		DstIP:       net.ParseIP("203.0.113.10"),
		DstPort:     443,
		AuditToken:  [32]byte{1},
		ClientHello: clientHelloForHost("unknown.example"),
	}); err != nil {
		t.Fatal(err)
	}
	conn := newWriteFailConn(request.Bytes())
	server := &Server{
		Decider: entryDecider{entry: decisionlog.Entry{
			Decision: decisionlog.DecisionDeny,
			Action:   string(decisionlog.DecisionDeny),
			Reason:   "host_unknown_no_prompt",
		}},
		Resolver:      StubResolver{},
		Log:           &decisionlog.Writer{},
		FrameDeadline: time.Second,
	}
	done := make(chan struct{})
	go func() {
		server.handleConn(conn)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		_ = conn.Close()
		<-done
		t.Fatal("handleConn kept reading after response write failure")
	}
}

type fakeFileInfo struct {
	mode os.FileMode
	uid  uint32
}

func (f fakeFileInfo) Name() string       { return "socket-dir" }
func (f fakeFileInfo) Size() int64        { return 0 }
func (f fakeFileInfo) Mode() os.FileMode  { return f.mode }
func (f fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f fakeFileInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeFileInfo) Sys() any           { return &syscall.Stat_t{Uid: f.uid} }

type testServer struct {
	path    string
	logPath string
}

func newTestServer(tb testing.TB, observeOnly bool, resolver IdentityResolver) testServer {
	return newTestServerWithBinder(tb, observeOnly, resolver, nil)
}

func newTestServerWithBinder(tb testing.TB, observeOnly bool, resolver IdentityResolver, binder daemon.DestBinder) testServer {
	return newTestServerWithBinderAndDeadline(tb, observeOnly, resolver, binder, 0)
}

func newTestServerWithBinderAndDeadline(tb testing.TB, observeOnly bool, resolver IdentityResolver, binder daemon.DestBinder, deadline time.Duration) testServer {
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
		Binder:      binder,
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
	go func() {
		serveDone <- (&Server{Decider: decider, Resolver: resolver, Log: log, FrameDeadline: deadline}).Serve(ctx, ln)
	}()
	tb.Cleanup(func() {
		cancel()
		_ = ln.Close()
		if err := <-serveDone; err != nil {
			tb.Errorf("Serve: %v", err)
		}
	})

	return testServer{path: path, logPath: logPath}
}

func newTestServerWithDecider(tb testing.TB, decider Decider, resolver IdentityResolver) testServer {
	tb.Helper()

	logPath := filepath.Join(tb.TempDir(), "decisions.log")
	log, err := decisionlog.Open(logPath)
	if err != nil {
		tb.Fatalf("open decision log: %v", err)
	}
	tb.Cleanup(func() { _ = log.Close() })

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

type entryDecider struct {
	entry decisionlog.Entry
}

func (d entryDecider) Decide(string, net.IP, procid.ProcInfo, signature.SignedIdentity) (decisionlog.Decision, decisionlog.Entry) {
	return d.entry.Decision, d.entry
}

func testSocketPath(tb testing.TB) string {
	tb.Helper()

	shortParent, err := os.MkdirTemp("", "nebridge-")
	if err != nil {
		tb.Fatalf("make short socket path: %v", err)
	}
	tb.Cleanup(func() {
		if err := os.RemoveAll(shortParent); err != nil {
			tb.Errorf("remove short socket path: %v", err)
		}
	})

	return filepath.Join(shortParent, "d", "s")
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

func (s testServer) waitForOnlyLogEntry(t *testing.T) decisionlog.Entry {
	t.Helper()
	var entries []decisionlog.Entry
	waitFor(t, func() bool {
		var err error
		entries, err = decisionlog.Read(s.logPath)
		return err == nil && len(entries) == 1
	})
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

func malformedRequestFrame(t *testing.T) []byte {
	t.Helper()
	var frame []byte
	frame = append(frame, 99)
	frame = append(frame, make([]byte, net.IPv6len)...)
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], 443)
	frame = append(frame, port[:]...)
	frame = append(frame, make([]byte, 32)...)
	frame = append(frame, 0, 0)
	if len(frame) != requestHeaderLen {
		t.Fatalf("malformed request header length = %d, want %d", len(frame), requestHeaderLen)
	}
	return frame
}

func waitFor(t *testing.T, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met within 2s")
}

type writeFailConn struct {
	mu     sync.Mutex
	input  *bytes.Reader
	closed chan struct{}
}

func newWriteFailConn(input []byte) *writeFailConn {
	return &writeFailConn{input: bytes.NewReader(input), closed: make(chan struct{})}
}

func (c *writeFailConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	if c.input.Len() > 0 {
		n, err := c.input.Read(p)
		c.mu.Unlock()
		return n, err
	}
	c.mu.Unlock()
	<-c.closed
	return 0, io.EOF
}

func (c *writeFailConn) Write([]byte) (int, error) {
	return 0, errors.New("forced write failure")
}

func (c *writeFailConn) Close() error {
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	return nil
}

func (c *writeFailConn) LocalAddr() net.Addr              { return stubAddr("local") }
func (c *writeFailConn) RemoteAddr() net.Addr             { return stubAddr("remote") }
func (c *writeFailConn) SetDeadline(time.Time) error      { return nil }
func (c *writeFailConn) SetReadDeadline(time.Time) error  { return nil }
func (c *writeFailConn) SetWriteDeadline(time.Time) error { return nil }

type stubAddr string

func (a stubAddr) Network() string { return string(a) }
func (a stubAddr) String() string  { return string(a) }
