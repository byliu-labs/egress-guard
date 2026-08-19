package daemon

import (
	"context"
	"crypto/tls"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/byliu-labs/egress-guard/internal/allowlist"
	"github.com/byliu-labs/egress-guard/internal/decisionlog"
	"github.com/byliu-labs/egress-guard/internal/drift"
	"github.com/byliu-labs/egress-guard/internal/procid"
	"github.com/byliu-labs/egress-guard/internal/signature"
)

func TestHandle_ObserveOnlyLogsWithoutEnforcing(t *testing.T) {
	upstream := newTLSEcho(t, "denied.example.com")
	defer upstream.Close()
	upHost, upPort := splitHostPort(upstream.Addr().String())

	fk := &fakeKernel{origs: make(map[string]struct {
		IP   net.IP
		Port int
	})}
	a := allowlist.New(allowlist.Config{
		Defaults: allowlist.Layer{Deny: []string{"denied.example.com"}},
	})
	logPath := filepath.Join(t.TempDir(), "decisions.log")
	dl, err := decisionlog.Open(logPath)
	if err != nil {
		t.Fatalf("decisionlog.Open: %v", err)
	}
	defer dl.Close()

	procIDStub := procid.NewStub()
	sigStub := signature.NewStub()
	sigStub.SetByExe("/usr/bin/curl", signature.SignedIdentity{Valid: true, TeamID: "TESTTEAM"})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d, err := New(Options{
		Listen:      "127.0.0.1:0",
		Kernel:      fk,
		Allow:       a,
		Log:         dl,
		ProcID:      procIDStub,
		Signature:   sigStub,
		ObserveOnly: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	go d.Run(ctx)
	addr := d.WaitListen()
	procIDStub.Set(addr.String(), procid.ProcInfo{PID: 4242, Exe: "/usr/bin/curl", Comm: "curl"})

	conn, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatalf("dial daemon: %v", err)
	}
	fk.setOrig(conn.LocalAddr().String(), net.ParseIP(upHost), upPort)

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         "denied.example.com",
		InsecureSkipVerify: true,
	})
	tlsConn.SetDeadline(time.Now().Add(3 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("handshake failed under ObserveOnly: %v", err)
	}
	tlsConn.Close()
	dl.Close()

	entries, err := decisionlog.Read(logPath)
	if err != nil {
		t.Fatalf("decisionlog.Read: %v", err)
	}
	var got *decisionlog.Entry
	for i := range entries {
		if entries[i].Host == "denied.example.com" && !entries[i].IsFlow() {
			got = &entries[i]
		}
	}
	if got == nil {
		t.Fatalf("no log entry for denied.example.com; entries=%+v", entries)
	}
	if got.Decision != decisionlog.DecisionObserve {
		t.Errorf("Decision = %q, want observe", got.Decision)
	}
	if got.Action != "deny" {
		t.Errorf("Action = %q, want deny", got.Action)
	}
	if got.Reason != "host_denylisted" {
		t.Errorf("Reason = %q, want host_denylisted", got.Reason)
	}
	if got.PID != 4242 {
		t.Errorf("PID = %d, want 4242", got.PID)
	}
	if got.TeamID != "TESTTEAM" || !got.SigValid {
		t.Errorf("TeamID=%q SigValid=%v, want TESTTEAM/true", got.TeamID, got.SigValid)
	}
	if got.DestIP != upHost {
		t.Errorf("DestIP = %q, want %q", got.DestIP, upHost)
	}
}

func TestHandle_ObserveOnlyKeepsObserveDecisionOnDialFailure(t *testing.T) {
	fk := &fakeKernel{origs: make(map[string]struct {
		IP   net.IP
		Port int
	})}
	a := allowlist.New(allowlist.Config{
		Defaults: allowlist.Layer{Deny: []string{"denied.example.com"}},
	})
	logPath := filepath.Join(t.TempDir(), "decisions.log")
	dl, err := decisionlog.Open(logPath)
	if err != nil {
		t.Fatalf("decisionlog.Open: %v", err)
	}
	defer dl.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d, err := New(Options{
		Listen:      "127.0.0.1:0",
		Kernel:      fk,
		Allow:       a,
		Log:         dl,
		ObserveOnly: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	go d.Run(ctx)
	addr := d.WaitListen()

	unused := unusedLocalPort(t)
	conn, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatalf("dial daemon: %v", err)
	}
	fk.setOrig(conn.LocalAddr().String(), net.ParseIP("127.0.0.1"), unused)

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         "denied.example.com",
		InsecureSkipVerify: true,
	})
	tlsConn.SetDeadline(time.Now().Add(3 * time.Second))
	_ = tlsConn.Handshake()
	tlsConn.Close()
	dl.Close()

	entries, err := decisionlog.Read(logPath)
	if err != nil {
		t.Fatalf("decisionlog.Read: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected a decision log entry")
	}
	got := entries[len(entries)-1]
	if got.Decision != decisionlog.DecisionObserve {
		t.Errorf("Decision = %q, want observe", got.Decision)
	}
	if got.Action != "deny" {
		t.Errorf("Action = %q, want original policy action deny", got.Action)
	}
	if !strings.HasPrefix(got.Reason, "net_error: upstream_dial_failed after host_denylisted:") {
		t.Errorf("Reason = %q, want net_error preserving policy reason", got.Reason)
	}
	at, err := time.Parse(time.RFC3339, got.Timestamp)
	if err != nil {
		t.Fatalf("decision timestamp: %v", err)
	}
	if live := d.lastSeen.at(drift.BaselinePairKey(got)); !live.Equal(at) {
		t.Errorf("flowless accepted decision advanced reference to %v, want %v", live, at)
	}
}

func unusedLocalPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen unused port: %v", err)
	}
	_, port := splitHostPort(ln.Addr().String())
	ln.Close()
	return port
}
