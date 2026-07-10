//go:build darwin

package procid

import (
	"net"
	"os"
	"strings"
	"testing"
)

// TestDarwin_LookupSelf opens a self-connected TCP pair and asserts that the
// procid layer recovers our own pid/exe by 4-tuple match against lsof.
func TestDarwin_LookupSelf(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	clientCh := make(chan net.Conn, 1)
	go func() {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Errorf("dial: %v", err)
			clientCh <- nil
			return
		}
		clientCh <- c
	}()
	server, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer server.Close()
	client := <-clientCh
	if client == nil {
		t.Fatalf("dial failed")
	}
	defer client.Close()

	l := defaultLookup()
	pi, err := l.LookupConn(server)
	if err != nil {
		t.Fatalf("LookupConn: %v", err)
	}
	if pi.PID != os.Getpid() {
		t.Errorf("PID = %d, want %d (self)", pi.PID, os.Getpid())
	}
	if pi.Exe == "" {
		t.Fatalf("Exe empty — procPidPath failed silently")
	}
	if !strings.Contains(pi.Exe, ".test") {
		t.Errorf("Exe = %q, want path containing .test (the test binary)", pi.Exe)
	}
	if pi.Comm == "" {
		t.Errorf("Comm empty — expected basename of exe")
	}
	t.Logf("observed: pi.Exe=%q pi.Comm=%q", pi.Exe, pi.Comm)
}
