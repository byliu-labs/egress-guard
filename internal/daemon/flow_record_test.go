package daemon

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/byliu-labs/egress-guard/internal/allowlist"
	"github.com/byliu-labs/egress-guard/internal/decisionlog"
	"github.com/byliu-labs/egress-guard/internal/procid"
	"github.com/byliu-labs/egress-guard/internal/signature"
)

func TestAllowedConnection_WritesCorrelatedFlowRecord(t *testing.T) {
	logPath, transferred := runAllowedConnectionForTest(t, 512)

	entries, err := decisionlog.Read(logPath)
	if err != nil {
		t.Fatal(err)
	}

	var decisions, flows []decisionlog.Entry
	for i := range entries {
		if entries[i].IsFlow() {
			flows = append(flows, entries[i])
		} else {
			decisions = append(decisions, entries[i])
		}
	}
	if len(decisions) != 1 {
		t.Fatalf("decision records = %d, want exactly 1: %+v", len(decisions), decisions)
	}
	if len(flows) != 1 {
		t.Fatalf("flow records = %d, want exactly 1: %+v", len(flows), flows)
	}
	decision := decisions[0]
	flow := flows[0]
	if decision.ConnID == "" {
		t.Fatal("decision record has no conn_id; the flow record cannot be correlated to it")
	}
	if flow.ConnID != decision.ConnID {
		t.Fatalf("flow conn_id %q != decision conn_id %q", flow.ConnID, decision.ConnID)
	}
	if flow.BytesUp != int64(transferred) {
		t.Errorf("bytes_up = %d, want %d", flow.BytesUp, transferred)
	}
	if flow.BytesDown == 0 {
		t.Error("bytes_down = 0, want bytes returned from upstream")
	}
	if flow.Host != decision.Host || flow.Exe != decision.Exe {
		t.Error("flow record lost the identity/host of its decision; it cannot be scored per (identity, host)")
	}
	if flow.DurationMS < 0 {
		t.Errorf("duration_ms = %d", flow.DurationMS)
	}
}

func TestDeniedConnection_WritesNoFlowRecord(t *testing.T) {
	logPath := runDeniedConnectionForTest(t)
	entries, err := decisionlog.Read(logPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsFlow() {
			t.Fatal("a denied connection produced a flow record; nothing was spliced, so there is nothing to report")
		}
	}
}

func TestAllowedConnection_LogsDecisionWhenReplayWriteFails(t *testing.T) {
	host := "allow.example"
	ctx, logPath, dl, d, fk, procIDStub, cancel := newFlowRecordDaemon(t, allowlist.Layer{Allow: []string{host}})
	defer cancel()
	defer dl.Close()
	d.dial = func(string, string) (net.Conn, error) {
		left, right := net.Pipe()
		right.Close()
		return writeFailConn{Conn: left}, nil
	}
	go d.Run(ctx)
	addr := d.WaitListen()
	procIDStub.Set(addr.String(), procid.ProcInfo{PID: 4242, Exe: "/usr/bin/curl", Comm: "curl"})

	conn, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatalf("dial daemon: %v", err)
	}
	defer conn.Close()
	fk.setOrig(conn.LocalAddr().String(), net.ParseIP("127.0.0.1"), 443)
	if _, err := conn.Write(spoofedClientHello(host)); err != nil {
		t.Fatalf("write ClientHello: %v", err)
	}
	waitForDecisionEntry(t, logPath)

	entries, err := decisionlog.Read(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want exactly one decision entry: %+v", len(entries), entries)
	}
	got := entries[0]
	if got.IsFlow() {
		t.Fatalf("write failure produced flow record: %+v", got)
	}
	if got.Decision != decisionlog.DecisionDeny {
		t.Fatalf("Decision = %q, want %q", got.Decision, decisionlog.DecisionDeny)
	}
	if !strings.HasPrefix(got.Reason, "upstream_write_failed: ") {
		t.Fatalf("Reason = %q, want upstream_write_failed", got.Reason)
	}
}

func runAllowedConnectionForTest(t *testing.T, payloadBytes int) (string, int) {
	t.Helper()
	host := "allow.example"
	hello := spoofedClientHello(host)
	responseBytes := 128
	helloRead := make(chan struct{})
	upstream := newRawFlowUpstream(t, len(hello), payloadBytes, responseBytes, helloRead)
	defer upstream.Close()
	upHost, upPort := splitHostPort(upstream.Addr().String())

	ctx, logPath, dl, d, fk, procIDStub, cancel := newFlowRecordDaemon(t, allowlist.Layer{Allow: []string{host}})
	defer cancel()
	defer dl.Close()
	go d.Run(ctx)
	addr := d.WaitListen()
	procIDStub.Set(addr.String(), procid.ProcInfo{PID: 4242, Exe: "/usr/bin/curl", Comm: "curl"})

	conn, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatalf("dial daemon: %v", err)
	}
	defer conn.Close()
	fk.setOrig(conn.LocalAddr().String(), net.ParseIP(upHost), upPort)
	if _, err := conn.Write(hello); err != nil {
		t.Fatalf("write ClientHello: %v", err)
	}
	select {
	case <-helloRead:
	case <-time.After(3 * time.Second):
		t.Fatal("upstream never received replayed ClientHello")
	}
	if _, err := conn.Write(bytes.Repeat([]byte("x"), payloadBytes)); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if len(got) != responseBytes {
		t.Fatalf("client read %d response bytes, want %d", len(got), responseBytes)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("close client connection: %v", err)
	}
	waitForSingleFlowAfterDecision(t, logPath)
	return logPath, payloadBytes
}

func runDeniedConnectionForTest(t *testing.T) string {
	t.Helper()
	host := "deny.example"
	ctx, logPath, dl, d, fk, procIDStub, cancel := newFlowRecordDaemon(t, allowlist.Layer{Deny: []string{host}})
	defer cancel()
	defer dl.Close()
	go d.Run(ctx)
	addr := d.WaitListen()
	procIDStub.Set(addr.String(), procid.ProcInfo{PID: 4242, Exe: "/usr/bin/curl", Comm: "curl"})

	conn, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatalf("dial daemon: %v", err)
	}
	defer conn.Close()
	fk.setOrig(conn.LocalAddr().String(), net.ParseIP("127.0.0.1"), unusedLocalPort(t))
	if _, err := conn.Write(spoofedClientHello(host)); err != nil {
		t.Fatalf("write ClientHello: %v", err)
	}
	waitForNoFlowAfterDecision(t, logPath)
	return logPath
}

func newFlowRecordDaemon(t *testing.T, defaults allowlist.Layer) (context.Context, string, *decisionlog.Writer, *Daemon, *fakeKernel, *procid.Stub, context.CancelFunc) {
	t.Helper()
	fk := &fakeKernel{origs: make(map[string]struct {
		IP   net.IP
		Port int
	})}
	a := allowlist.New(allowlist.Config{Defaults: defaults})
	logPath := filepath.Join(t.TempDir(), "decisions.log")
	dl, err := decisionlog.Open(logPath)
	if err != nil {
		t.Fatalf("decisionlog.Open: %v", err)
	}
	procIDStub := procid.NewStub()
	sigStub := signature.NewStub()
	sigStub.SetByExe("/usr/bin/curl", signature.SignedIdentity{Valid: true, TeamID: "TESTTEAM"})
	ctx, cancel := context.WithCancel(context.Background())
	d, err := New(Options{
		Listen:    "127.0.0.1:0",
		Kernel:    fk,
		Allow:     a,
		Log:       dl,
		ProcID:    procIDStub,
		Signature: sigStub,
	})
	if err != nil {
		cancel()
		t.Fatalf("New: %v", err)
	}
	return ctx, logPath, dl, d, fk, procIDStub, cancel
}

func newRawFlowUpstream(t *testing.T, helloBytes, payloadBytes, responseBytes int, helloRead chan<- struct{}) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		if _, err := io.ReadFull(c, make([]byte, helloBytes)); err != nil {
			return
		}
		close(helloRead)
		if _, err := io.ReadFull(c, make([]byte, payloadBytes)); err != nil {
			return
		}
		_, _ = c.Write(bytes.Repeat([]byte("y"), responseBytes))
	}()
	return ln
}

func waitForSingleFlowAfterDecision(t *testing.T, logPath string) {
	t.Helper()
	waitForLogEntry(t, logPath, func(e decisionlog.Entry) bool { return !e.IsFlow() })
	deadline := time.Now().Add(500 * time.Millisecond)
	seenFlow := false
	for time.Now().Before(deadline) {
		entries, err := decisionlog.Read(logPath)
		if err == nil {
			flows := 0
			for _, e := range entries {
				if e.IsFlow() {
					flows++
				}
			}
			if flows > 1 {
				t.Fatalf("flow records = %d, want exactly 1: %+v", flows, entries)
			}
			if flows == 1 {
				seenFlow = true
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !seenFlow {
		t.Fatal("no flow record found in the log -- the connection closed and its bytes were discarded")
	}
}

func waitForNoFlowAfterDecision(t *testing.T, logPath string) {
	t.Helper()
	waitForLogEntry(t, logPath, func(e decisionlog.Entry) bool { return !e.IsFlow() })
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		entries, err := decisionlog.Read(logPath)
		if err == nil {
			for _, e := range entries {
				if e.IsFlow() {
					t.Fatalf("unexpected flow record after denied decision: %+v", e)
				}
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func waitForDecisionEntry(t *testing.T, logPath string) {
	t.Helper()
	waitForLogEntry(t, logPath, func(e decisionlog.Entry) bool { return !e.IsFlow() })
}

func waitForLogEntry(t *testing.T, logPath string, match func(decisionlog.Entry) bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		entries, err := decisionlog.Read(logPath)
		if err == nil {
			for _, e := range entries {
				if match(e) {
					return
				}
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for matching log entry in %s", logPath)
}

type writeFailConn struct {
	net.Conn
}

func (c writeFailConn) Write([]byte) (int, error) {
	return 0, errors.New("forced replay write failure")
}
