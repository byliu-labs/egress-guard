package daemon

import (
	"net"
	"os"
	"strings"
	"testing"

	"github.com/byliu-labs/egress-guard/internal/allowlist"
	"github.com/byliu-labs/egress-guard/internal/decisionlog"
	"github.com/byliu-labs/egress-guard/internal/idle"
	"github.com/byliu-labs/egress-guard/internal/procid"
)

// The bit must survive the writer to disk, not merely exist on the struct.
func TestDeniedConnection_LogsUserActiveToDisk(t *testing.T) {
	host := "deny.example"
	stub := idle.NewStub()
	stub.SetActive(false)
	ctx, logPath, log, d, kernel, procID, cancel := newFlowRecordDaemon(t, allowlist.Layer{Deny: []string{host}})
	defer cancel()
	defer log.Close()
	d.opts.Idle = stub

	go d.Run(ctx)
	addr := d.WaitListen()
	procID.Set(addr.String(), procid.ProcInfo{PID: 4242, Exe: "/usr/bin/curl", Comm: "curl"})
	conn, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatalf("dial daemon: %v", err)
	}
	defer conn.Close()
	kernel.setOrig(conn.LocalAddr().String(), net.ParseIP("127.0.0.1"), unusedLocalPort(t))
	if _, err := conn.Write(spoofedClientHello(host)); err != nil {
		t.Fatalf("write ClientHello: %v", err)
	}
	waitForDecisionEntry(t, logPath)

	entries, err := decisionlog.Read(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("no entries written")
	}
	if entries[0].UserActive == nil {
		t.Fatal("user_active missing from written record")
	}
	if *entries[0].UserActive {
		t.Errorf("user_active = true, want false")
	}

	// Decoding through the same struct that wrote the line cannot catch a
	// renamed JSON tag. Downstream scoring reads the literal key, so assert
	// the bytes: both that the name is "user_active" and that a false value
	// is written rather than omitted.
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"user_active":false`) {
		t.Errorf(`on-disk record lacks "user_active":false; got %s`, raw)
	}
}
