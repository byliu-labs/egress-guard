package nebridge

import (
	"net"
	"testing"

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
