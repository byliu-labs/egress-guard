package daemon

// Tests that the SNI↔IP binding does NOT break honest traffic: when the client
// connects to a legitimate address of the allowlisted host, the binding passes
// and the connection splices through as before.

import (
	"context"
	"crypto/tls"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/byliu-labs/egress-guard/internal/allowlist"
	"github.com/byliu-labs/egress-guard/internal/decisionlog"
	"github.com/byliu-labs/egress-guard/internal/dnsbind"
)

// TestBinding_HonestTrafficPasses points the daemon at a real upstream and
// tells the binder that the allowed host resolves to that upstream's IP. The
// TLS handshake must complete — the binding is transparent to honest clients.
func TestBinding_HonestTrafficPasses(t *testing.T) {
	upstream := newTLSEcho(t, "test.example.com")
	defer upstream.Close()
	upHost, upPort := splitHostPort(upstream.Addr().String())

	binder := dnsbind.NewWithResolver(stubResolver{
		"test.example.com": {net.ParseIP(upHost)},
	})

	fk := &fakeKernel{origs: make(map[string]struct {
		IP   net.IP
		Port int
	})}
	a := allowlist.New(allowlist.Config{
		Defaults: allowlist.Layer{Allow: []string{"test.example.com"}},
	})
	bl, _ := decisionlog.Open(filepath.Join(t.TempDir(), "blocked.log"))
	defer bl.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d, err := New(Options{Listen: "127.0.0.1:0", Kernel: fk, Allow: a, Log: bl, Binder: binder})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	go d.Run(ctx)
	addr := d.WaitListen()

	conn, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatalf("dial daemon: %v", err)
	}
	fk.setOrig(conn.LocalAddr().String(), net.ParseIP(upHost), upPort)

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         "test.example.com",
		InsecureSkipVerify: true, // test-only
	})
	tlsConn.SetDeadline(time.Now().Add(3 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("honest handshake failed under binding: %v", err)
	}
	tlsConn.Close()
}
