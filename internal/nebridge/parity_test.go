package nebridge

import (
	"strings"
	"testing"

	"github.com/byliu-labs/egress-guard/internal/tlsparse"
)

func TestBridgeSNIParity(t *testing.T) {
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
			want, err := tlsparse.ParseSNI(clientHello)
			if err != nil {
				t.Fatalf("ParseSNI: %v", err)
			}

			response := server.request(t, "", clientHello)
			if response.Host != want {
				t.Fatalf("Response.Host = %q, want %q", response.Host, want)
			}
			if response.Verdict != VerdictAllow {
				t.Fatalf("Verdict = %v, want allow", response.Verdict)
			}
		})
	}
}

func TestBridgeSNIParity_NoSNI(t *testing.T) {
	server := newTestServer(t, true, StubResolver{})

	response := server.request(t, "", tlsparse.BuildClientHelloForTest("", false))

	if response.Verdict != VerdictDrop {
		t.Fatalf("Verdict = %v, want drop", response.Verdict)
	}
	if !strings.Contains(response.Reason, "no SNI") {
		t.Fatalf("Reason = %q, want to contain no SNI", response.Reason)
	}
}
