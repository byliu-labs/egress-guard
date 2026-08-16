package nebridge

import (
	"net"
	"strings"
	"testing"

	"github.com/byliu-labs/egress-guard/internal/allowlist"
	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/daemon"
	"github.com/byliu-labs/egress-guard/internal/decisionlog"
	"github.com/byliu-labs/egress-guard/internal/kernel"
	"github.com/byliu-labs/egress-guard/internal/procid"
	"github.com/byliu-labs/egress-guard/internal/signature"
	"github.com/byliu-labs/egress-guard/internal/tlsparse"
)

func TestBridge_FrameCarriesClientHelloIntact(t *testing.T) {
	maxHost := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	hosts := []string{
		"example.com",
		"a.b.c.example",
		"xn--80ak6aa92e.com",
		maxHost,
	}
	server := newTestServer(t, true, StubResolver{})

	for _, host := range hosts {
		t.Run(host, func(t *testing.T) {
			clientHello := tlsparse.BuildClientHelloForTest(host, true)

			response := server.request(t, "", clientHello)
			if response.Host != host {
				t.Fatalf("Response.Host = %q, want %q", response.Host, host)
			}
			if response.Verdict != VerdictAllow {
				t.Fatalf("Verdict = %v, want allow", response.Verdict)
			}
		})
	}
}

func TestBridge_FrameCarriesClientHelloIntact_NoSNI(t *testing.T) {
	server := newTestServer(t, true, StubResolver{})

	response := server.request(t, "", tlsparse.BuildClientHelloForTest("", false))

	if response.Verdict != VerdictDrop {
		t.Fatalf("Verdict = %v, want drop", response.Verdict)
	}
	if !strings.Contains(response.Reason, "no SNI") {
		t.Fatalf("Reason = %q, want to contain no SNI", response.Reason)
	}
}

func TestParity_PfAndBridgeAgree(t *testing.T) {
	cases := []struct {
		name        string
		host        string
		catalogTOML string
		observeOnly bool
	}{
		{"catalog allow", "pypi.org", pypiAllowTOML, false},
		{"catalog deny", "evil.example", evilDenyTOML, false},
		{"unknown host", "unknown.example", "", false},
		{"unknown host, observe mode", "unknown.example", "", true},
		{"catalog deny, observe mode", "evil.example", evilDenyTOML, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pi := procid.ProcInfo{PID: 1234, Exe: "/usr/bin/curl", Comm: "curl"}
			sig := signature.SignedIdentity{}
			dstIP := net.ParseIP("203.0.113.10")

			d := newParityDaemon(t, tc.catalogTOML, tc.observeOnly)
			wantDec, wantEntry := d.Decide(tc.host, dstIP, pi, sig)

			server := newTestServerWithDecider(t, d, StubResolver{Proc: pi, Sig: sig})
			resp := server.request(t, "", tlsparse.BuildClientHelloForTest(tc.host, true))

			if got, want := resp.Verdict, expectedBridgeVerdict(wantDec); got != want {
				t.Errorf("bridge verdict = %v, pf decision %q maps to %v", got, wantDec, want)
			}
			if resp.Reason != wantEntry.Reason {
				t.Errorf("bridge reason = %q, pf reason = %q", resp.Reason, wantEntry.Reason)
			}

			entries, err := decisionlog.Read(server.logPath)
			if err != nil {
				t.Fatal(err)
			}
			last := entries[len(entries)-1]
			if last.Decision != wantEntry.Decision {
				t.Errorf("bridge logged decision %q, pf decided %q", last.Decision, wantEntry.Decision)
			}
			if last.TrustTier != wantEntry.TrustTier {
				t.Errorf("bridge logged trust_tier %q, pf %q -- the two tiers must never diverge",
					last.TrustTier, wantEntry.TrustTier)
			}
		})
	}
}

func expectedBridgeVerdict(dec decisionlog.Decision) Verdict {
	switch dec {
	case decisionlog.DecisionAllow, decisionlog.DecisionObserve:
		return VerdictAllow
	default:
		return VerdictDrop
	}
}

func newParityDaemon(t *testing.T, catalogTOML string, observeOnly bool) *daemon.Daemon {
	t.Helper()
	var c *catalog.Catalog
	if catalogTOML != "" {
		loaded, err := catalog.Load([]byte(catalogTOML))
		if err != nil {
			t.Fatalf("load catalog: %v", err)
		}
		c = loaded
	}
	d, err := daemon.New(daemon.Options{
		Listen:      "127.0.0.1:0",
		Kernel:      kernel.Default(),
		Allow:       allowlist.New(allowlist.Config{}),
		Log:         &decisionlog.Writer{},
		Catalog:     c,
		ObserveOnly: observeOnly,
	})
	if err != nil {
		t.Fatalf("new daemon: %v", err)
	}
	return d
}

const pypiAllowTOML = `
[[entry]]
schema_version = 1
layer = "baseline"
confidence = "medium"
evidence = "test fixture"
explanation = "test fixture"

[entry.identity]
exe_basename = "curl"

[[entry.expected_destinations]]
host = "pypi.org"
`

const evilDenyTOML = `
[[entry]]
schema_version = 1
layer = "baseline"
confidence = "medium"
evidence = "test fixture"
explanation = "test fixture"
never = ["evil.example"]

[entry.identity]
exe_basename = "curl"
`
