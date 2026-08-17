package nebridge

import (
	"net"
	"os"
	"testing"
	"time"
)

func TestServer_StalledPeerIsDisconnected(t *testing.T) {
	server := newTestServer(t, true, StubResolver{})
	conn, err := net.Dial("unix", server.path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte{0x01}); err != nil {
		t.Fatal(err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(requestReadTimeout + 3*time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	if err == nil {
		return
	}
	if os.IsTimeout(err) {
		t.Fatalf("server still holding a half-open connection after %v -- a stalled peer pins a goroutine and fd forever", requestReadTimeout)
	}
}
