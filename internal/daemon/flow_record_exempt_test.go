package daemon

import (
	"bytes"
	"io"
	"net"
	"testing"

	"github.com/byliu-labs/egress-guard/internal/allowlist"
	"github.com/byliu-labs/egress-guard/internal/decisionlog"
	"github.com/byliu-labs/egress-guard/internal/exempt"
	"github.com/byliu-labs/egress-guard/internal/procid"
	"github.com/byliu-labs/egress-guard/internal/signature"
)

// The exempt fast-path is the second writeFlow call site. It splices without
// parsing SNI, so it exercises a different branch than the filtered path, and
// it was previously untested — internal/daemon/decision_test.go skips the
// exempt splice with "covered in integration tests", which tests/integration
// does not do.
func TestExemptConnection_WritesExactlyOneFlowRecord(t *testing.T) {
	const payloadBytes = 256
	const responseBytes = 64

	upstream := newRawEchoUpstream(t, payloadBytes, responseBytes)
	defer upstream.Close()
	upHost, upPort := splitHostPort(upstream.Addr().String())

	ctx, logPath, dl, d, fk, procIDStub, cancel := newFlowRecordDaemon(t, allowlist.Layer{})
	defer cancel()
	defer dl.Close()

	// Safari is exempt in the shipped defaults when validly signed.
	exemptCat, err := exempt.LoadDefault()
	if err != nil {
		t.Fatalf("exempt.LoadDefault: %v", err)
	}
	d.opts.Exempt = exemptCat

	exe := "/Applications/Safari.app/Contents/MacOS/Safari"
	sigStub := signature.NewStub()
	sigStub.SetByExe(exe, signature.SignedIdentity{
		Valid: true, TeamID: "APPLE", BundleID: "com.apple.Safari",
	})
	d.opts.Signature = sigStub

	go d.Run(ctx)
	addr := d.WaitListen()
	procIDStub.Set(addr.String(), procid.ProcInfo{PID: 7777, Exe: exe, Comm: "Safari"})

	conn, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatalf("dial daemon: %v", err)
	}
	defer conn.Close()
	fk.setOrig(conn.LocalAddr().String(), net.ParseIP(upHost), upPort)

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
	decision, flow := decisions[0], flows[0]

	if decision.Reason != "exempt_app" {
		t.Errorf("decision reason = %q, want exempt_app", decision.Reason)
	}
	if decision.ConnID == "" {
		t.Fatal("exempt decision record has no conn_id; its flow record cannot be correlated")
	}
	if flow.ConnID != decision.ConnID {
		t.Errorf("flow conn_id %q != decision conn_id %q", flow.ConnID, decision.ConnID)
	}
	if flow.BytesUp != int64(payloadBytes) {
		t.Errorf("bytes_up = %d, want %d", flow.BytesUp, payloadBytes)
	}
	if flow.BytesDown != int64(responseBytes) {
		t.Errorf("bytes_down = %d, want %d", flow.BytesDown, responseBytes)
	}
	if flow.Exe != decision.Exe || flow.ExeSHA256 != decision.ExeSHA256 || flow.TeamID != decision.TeamID {
		t.Errorf("flow identity (%q/%q/%q) != decision identity (%q/%q/%q)",
			flow.Exe, flow.ExeSHA256, flow.TeamID,
			decision.Exe, decision.ExeSHA256, decision.TeamID)
	}
	if flow.DurationMS < 0 {
		t.Errorf("duration_ms = %d", flow.DurationMS)
	}
}

// newRawEchoUpstream accepts one connection, reads payloadBytes, then writes
// responseBytes and closes. Unlike newRawFlowUpstream it expects no replayed
// ClientHello, because the exempt fast-path never parses one.
func newRawEchoUpstream(t *testing.T, payloadBytes, responseBytes int) net.Listener {
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
		if _, err := io.ReadFull(c, make([]byte, payloadBytes)); err != nil {
			return
		}
		_, _ = c.Write(bytes.Repeat([]byte("y"), responseBytes))
	}()
	return ln
}
