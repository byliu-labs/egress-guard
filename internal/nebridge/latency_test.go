package nebridge

import (
	"net"
	"sort"
	"testing"
	"time"

	"github.com/byliu-labs/egress-guard/internal/tlsparse"
)

const bridgeLatencyRounds = 10_000

func TestBridgeP99Latency(t *testing.T) {
	bridge := newLatencyBridge(t)
	durations := make([]time.Duration, bridgeLatencyRounds)

	for i := range durations {
		started := time.Now()
		response, err := bridge.roundTrip()
		durations[i] = time.Since(started)
		if err != nil {
			t.Fatalf("round trip %d: %v", i, err)
		}
		if response.Verdict != VerdictAllow {
			t.Fatalf("round trip %d verdict = %v, want allow", i, response.Verdict)
		}
	}

	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	p50 := percentile(durations, 50)
	p99 := percentile(durations, 99)
	max := durations[len(durations)-1]
	t.Logf("bridge round-trip: p50=%s p99=%s max=%s", p50, p99, max)
	if p99 > 20*time.Millisecond {
		t.Fatalf("bridge p99 = %s, want <= %s", p99, 20*time.Millisecond)
	}
}

func BenchmarkBridgeRoundTrip(b *testing.B) {
	bridge := newLatencyBridge(b)

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		response, err := bridge.roundTrip()
		if err != nil {
			b.Fatal(err)
		}
		if response.Verdict != VerdictAllow {
			b.Fatalf("verdict = %v, want allow", response.Verdict)
		}
	}
}

type latencyBridge struct {
	conn    net.Conn
	request Request
}

func newLatencyBridge(tb testing.TB) latencyBridge {
	tb.Helper()

	server := newTestServer(tb, false, StubResolver{})
	conn, err := net.Dial("unix", server.path)
	if err != nil {
		tb.Fatalf("dial server: %v", err)
	}
	tb.Cleanup(func() { _ = conn.Close() })

	return latencyBridge{
		conn: conn,
		request: Request{
			DstIP:       net.ParseIP("203.0.113.10"),
			DstPort:     443,
			AuditToken:  [32]byte{1},
			ClientHello: tlsparse.BuildClientHelloForTest("allow.example", true),
		},
	}
}

func (b latencyBridge) roundTrip() (Response, error) {
	if err := EncodeRequest(b.conn, b.request); err != nil {
		return Response{}, err
	}
	return DecodeResponse(b.conn)
}

func percentile(durations []time.Duration, percentage int) time.Duration {
	return durations[(len(durations)-1)*percentage/100]
}
