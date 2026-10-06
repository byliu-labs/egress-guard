//go:build darwin

package kernel

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"unsafe"
)

func TestPfNatLookMatchesXNULayout(t *testing.T) {
	var nl pfNatLook
	if got := unsafe.Sizeof(nl); got != 84 {
		t.Errorf("size = %d, want 84", got)
	}
	for _, field := range []struct {
		name      string
		got, want uintptr
	}{
		{"sxport", unsafe.Offsetof(nl.sxport), 64},
		{"rdxport", unsafe.Offsetof(nl.rdxport), 76},
		{"af", unsafe.Offsetof(nl.af), 80},
		{"direction", unsafe.Offsetof(nl.direction), 83},
	} {
		if field.got != field.want {
			t.Errorf("%s offset = %d, want %d", field.name, field.got, field.want)
		}
	}
}

func TestPfNatLookXportRoundTrip(t *testing.T) {
	var nl pfNatLook
	binary.BigEndian.PutUint16(nl.sxport[:2], 443)
	if got := binary.BigEndian.Uint16(nl.sxport[:2]); got != 443 {
		t.Errorf("sxport = %d, want 443", got)
	}
}

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
	if got != 0xC0544417 {
		t.Errorf("diocNatlook() = 0x%x, want 0xC0544417", got)
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
