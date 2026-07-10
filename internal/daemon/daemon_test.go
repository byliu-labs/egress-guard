package daemon

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/byliu-labs/egress-guard/internal/allowlist"
	"github.com/byliu-labs/egress-guard/internal/decisionlog"
)

// fakeKernel implements kernel.RulesInstaller for tests. Original-dst is
// pulled from a remote-addr → fake-original-dst map populated by the test.
type fakeKernel struct {
	mu    sync.Mutex
	origs map[string]struct {
		IP   net.IP
		Port int
	}
}

func (f *fakeKernel) Install(int) error          { return nil }
func (f *fakeKernel) Uninstall() error           { return nil }
func (f *fakeKernel) IsInstalled() (bool, error) { return true, nil }

// OriginalDest polls until the test populates the entry (or 500 ms elapses).
// This avoids a setup race: the daemon goroutine calls OriginalDest before the
// test has had a chance to call setOrig after net.Dial returns.
func (f *fakeKernel) OriginalDest(c net.Conn) (net.IP, int, error) {
	key := c.RemoteAddr().String()
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		f.mu.Lock()
		o, ok := f.origs[key]
		f.mu.Unlock()
		if ok {
			return o.IP, o.Port, nil
		}
		time.Sleep(time.Millisecond)
	}
	return nil, 0, errors.New("no original-dst recorded for " + key)
}

func (f *fakeKernel) setOrig(remoteAddr string, ip net.IP, port int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.origs[remoteAddr] = struct {
		IP   net.IP
		Port int
	}{ip, port}
}

// TestDaemon_Allow_SplicesThrough boots a real upstream TLS server, points the
// daemon at it via the fake kernel, and confirms a TLS client gets through.
func TestDaemon_Allow_SplicesThrough(t *testing.T) {
	upstream := newTLSEcho(t, "test.example.com")
	defer upstream.Close()

	upstreamHost, upstreamPort := splitHostPort(upstream.Addr().String())

	fk := &fakeKernel{origs: make(map[string]struct {
		IP   net.IP
		Port int
	})}
	a := allowlist.New(allowlist.Config{
		Defaults: allowlist.Layer{Allow: []string{"test.example.com"}},
	})
	logFile := filepath.Join(t.TempDir(), "blocked.log")
	bl, _ := decisionlog.Open(logFile)
	defer bl.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d, err := New(Options{
		Listen: "127.0.0.1:0",
		Kernel: fk,
		Allow:  a,
		Log:    bl,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	go d.Run(ctx)
	addr := d.WaitListen()

	conn, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatalf("dial daemon: %v", err)
	}
	fk.setOrig(conn.LocalAddr().String(), net.ParseIP(upstreamHost), upstreamPort)

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         "test.example.com",
		InsecureSkipVerify: true, // test-only
	})
	tlsConn.SetDeadline(time.Now().Add(3 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	tlsConn.Close()
}

// TestDaemon_Deny_BlocksConnection verifies a denied SNI fails to handshake and
// produces a block-log entry.
func TestDaemon_Deny_BlocksConnection(t *testing.T) {
	fk := &fakeKernel{origs: map[string]struct {
		IP   net.IP
		Port int
	}{}}
	a := allowlist.New(allowlist.Config{
		Defaults: allowlist.Layer{Allow: []string{"only.allowed.com"}},
	})
	logFile := filepath.Join(t.TempDir(), "blocked.log")
	bl, _ := decisionlog.Open(logFile)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d, _ := New(Options{Listen: "127.0.0.1:0", Kernel: fk, Allow: a, Log: bl})
	go d.Run(ctx)
	addr := d.WaitListen()

	conn, _ := net.Dial("tcp", addr.String())
	fk.setOrig(conn.LocalAddr().String(), net.IPv4(192, 0, 2, 1), 443)

	tc := tls.Client(conn, &tls.Config{ServerName: "evil.example.com", InsecureSkipVerify: true})
	tc.SetDeadline(time.Now().Add(2 * time.Second))
	err := tc.Handshake()
	if err == nil {
		t.Fatal("expected handshake to fail (denied)")
	}
	conn.Close()

	bl.Close()
	stat, _ := os.Stat(logFile)
	if stat == nil || stat.Size() == 0 {
		t.Error("expected block-log to have at least one entry")
	}
}

// helpers
func splitHostPort(s string) (string, int) {
	host, port, _ := net.SplitHostPort(s)
	var p int
	for _, c := range port {
		p = p*10 + int(c-'0')
	}
	return host, p
}

// newTLSEcho returns a TLS server that uses a self-signed cert for sniName.
func newTLSEcho(t *testing.T, sniName string) net.Listener {
	t.Helper()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: sniName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{sniName},
	}
	der, _ := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(io.Discard, c)
			}(c)
		}
	}()
	return ln
}
