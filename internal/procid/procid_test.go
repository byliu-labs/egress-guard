package procid

import (
	"net"
	"testing"
)

func TestStub_KeyByLocalAddr(t *testing.T) {
	s := NewStub()
	s.Set("127.0.0.1:55555", ProcInfo{PID: 42, Exe: "/bin/curl", Comm: "curl"})

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	// net.Pipe addrs aren't real TCP — verify we get the zero value when key absent.
	got, err := s.LookupConn(c1)
	if err == nil && got.PID != 0 {
		t.Errorf("LookupConn(net.Pipe) = %+v, want zero", got)
	}
}
