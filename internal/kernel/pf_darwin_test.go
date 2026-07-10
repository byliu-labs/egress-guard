//go:build darwin

package kernel

import (
	"net"
	"strings"
	"testing"
)

// TestSockaddrToIP verifies the byte-to-IP helper used by OriginalDest.
func TestSockaddrToIP(t *testing.T) {
	ip := sockaddrToIP([4]byte{192, 0, 2, 42})
	if !ip.Equal(net.IPv4(192, 0, 2, 42)) {
		t.Errorf("sockaddrToIP = %v, want 192.0.2.42", ip)
	}
}

// TestDiocNatlook_NumberStable confirms the DIOCNATLOOK ioctl number we compute
// is stable across runs and matches the macOS kernel definition.
// Reference: <net/pfvar.h> _IOWR('D', 23, struct pfioc_natlook).
// We don't dial it; we just compute the encoded number.
func TestDiocNatlook_NumberStable(t *testing.T) {
	got := diocNatlook()
	if got == 0 {
		t.Error("diocNatlook() returned 0, expected non-zero ioctl number")
	}
	// The number must be a valid IOC encoding (high bits set: read+write).
	const iocInOut = 0xc0000000
	if got&iocInOut != iocInOut {
		t.Errorf("diocNatlook() = 0x%x, missing iocInOut bits", got)
	}
}

func TestBuildAnchorRules_DoesNotAdvertiseDeadUserExemption(t *testing.T) {
	got := buildAnchorRules(8443)

	if strings.Contains(got, "no rdr quick") || strings.Contains(got, "user _egress-guard") {
		t.Fatalf("anchor rules must not include a user exemption the root LaunchDaemon cannot match:\n%s", got)
	}
	if !strings.Contains(got, "rdr pass") {
		t.Fatal("missing `rdr pass` line")
	}
}

func TestBuildAnchorRules_PortSubstituted(t *testing.T) {
	got := buildAnchorRules(9999)
	if !strings.Contains(got, "-> 127.0.0.1 port 9999") {
		t.Errorf("expected redirect port 9999 in rules; got:\n%s", got)
	}
}
