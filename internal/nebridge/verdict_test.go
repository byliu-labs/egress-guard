package nebridge

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/byliu-labs/egress-guard/internal/decisionlog"
	"github.com/byliu-labs/egress-guard/internal/procid"
	"github.com/byliu-labs/egress-guard/internal/signature"
	"github.com/byliu-labs/egress-guard/internal/tlsparse"
)

func TestVerdictFor_UnknownDecisionDrops(t *testing.T) {
	cases := []struct {
		name string
		dec  decisionlog.Decision
		want Verdict
	}{
		{"allow", decisionlog.DecisionAllow, VerdictAllow},
		{"observe", decisionlog.DecisionObserve, VerdictAllow},
		{"deny", decisionlog.DecisionDeny, VerdictDrop},
		{"zero value", decisionlog.Decision(""), VerdictDrop},
		{"future hold state", decisionlog.Decision("hold"), VerdictDrop},
		{"typo", decisionlog.Decision("Allow"), VerdictDrop},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := verdictFor(tc.dec); got != tc.want {
				t.Fatalf("verdictFor(%q) = %v, want %v -- an unrecognized decision must never authorize egress",
					tc.dec, got, tc.want)
			}
		})
	}
}

func TestServer_UnsetDecisionYieldsDrop(t *testing.T) {
	server := newTestServerWithDecider(t, deciderFunc(func(string, net.IP, procid.ProcInfo, signature.SignedIdentity) (decisionlog.Decision, decisionlog.Entry) {
		return decisionlog.Decision(""), decisionlog.Entry{Reason: "unclassified"}
	}), StubResolver{})

	resp := server.request(t, "", tlsparse.BuildClientHelloForTest("example.com", true))
	if resp.Verdict != VerdictDrop {
		t.Fatalf("verdict = %v, want drop -- an unclassified entry authorized the connection", resp.Verdict)
	}
}

type deciderFunc func(string, net.IP, procid.ProcInfo, signature.SignedIdentity) (decisionlog.Decision, decisionlog.Entry)

func (f deciderFunc) Decide(host string, dstIP net.IP, pi procid.ProcInfo, sig signature.SignedIdentity) (decisionlog.Decision, decisionlog.Entry) {
	return f(host, dstIP, pi, sig)
}

func TestServer_MalformedFrameDeniesAndLogs(t *testing.T) {
	server := newTestServer(t, true, StubResolver{})

	conn, err := net.Dial("unix", server.path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte{0x01, 0x02, 0x03, 0x04}); err != nil {
		t.Fatal(err)
	}
	if unixConn, ok := conn.(*net.UnixConn); ok {
		_ = unixConn.CloseWrite()
	}

	buf := make([]byte, 64)
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, _ := conn.Read(buf)
	if n == 0 {
		t.Fatal("server sent no response to a malformed frame -- the provider's default would decide the flow")
	}

	entries, err := decisionlog.Read(server.logPath)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, entry := range entries {
		if !strings.Contains(entry.Reason, "frame_decode_failed") {
			continue
		}
		found = true
		if entry.Decision != decisionlog.DecisionDeny {
			t.Errorf("decode failure logged as %q, want deny", entry.Decision)
		}
		if entry.TrustTier != decisionlog.TierDefault {
			t.Errorf("decode failure trust tier = %q, want default", entry.TrustTier)
		}
	}
	if !found {
		t.Fatal("a malformed frame produced no frame_decode_failed decision-log entry")
	}
}
