//go:build darwin

package kernel

import (
	"encoding/binary"
	"errors"
	"net"
	"reflect"
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

// Anchor names and rule forms from the maintainer's root pfctl output on issue #11.
const issue11MainNat = `nat-anchor "com.apple/*" all
rdr-anchor "com.apple/*" all
rdr-anchor "com.apple.internet-sharing" all
`
const issue11MainRules = `scrub-anchor "com.apple/*" all fragment reassemble
anchor "com.apple/*" all
anchor "com.apple.internet-sharing" all
`
const issue11LeafNat = `rdr pass on lo0 inet proto tcp from any to any port = 443 -> 127.0.0.1 port 8443
rdr pass inet proto tcp from any to any port = 443 -> 127.0.0.1 port 8443
`

func stubPfctl(t *testing.T, nat, rules string) *[]string {
	t.Helper()
	oldRun := runPfctl
	var calls []string
	runPfctl = func(args ...string) ([]byte, error) {
		key := strings.Join(args, " ")
		calls = append(calls, key)
		switch key {
		case "-a egress-guard -sn":
			return []byte(issue11LeafNat), nil
		case "-s nat":
			return []byte(nat), nil
		case "-s rules":
			return []byte(rules), nil
		default:
			t.Fatalf("unexpected pfctl %s", key)
			return nil, nil
		}
	}
	t.Cleanup(func() { runPfctl = oldRun })
	return &calls
}

func TestIsInstalledFailsWhenAnchorLoadedButUnreachable(t *testing.T) {
	calls := stubPfctl(t, issue11MainNat, issue11MainRules)
	installed, err := (&pfDarwin{}).IsInstalled()
	if installed || !errors.Is(err, ErrAnchorUnreachable) {
		t.Fatalf("IsInstalled = (%v, %v), want (false, ErrAnchorUnreachable)", installed, err)
	}
	if want := []string{"-a egress-guard -sn", "-s nat", "-s rules"}; !reflect.DeepEqual(*calls, want) {
		t.Fatalf("pfctl calls = %v, want %v", *calls, want)
	}
}

// rdr reaching the leaf is not enough: the filter ruleset must traverse it too.
func TestIsInstalledFailsWhenOnlyRdrAnchorIsReachable(t *testing.T) {
	stubPfctl(t, issue11MainNat+"rdr-anchor \"egress-guard\" all\n", issue11MainRules)
	installed, err := (&pfDarwin{}).IsInstalled()
	if installed || !errors.Is(err, ErrAnchorUnreachable) {
		t.Fatalf("IsInstalled = (%v, %v), want (false, ErrAnchorUnreachable)", installed, err)
	}
}

func TestIsInstalledPassesWhenLoadedRulesReachAnchor(t *testing.T) {
	for _, tc := range []struct{ name, nat, rules string }{
		{"exact", issue11MainNat + "rdr-anchor \"egress-guard\" all\n", issue11MainRules + "anchor \"egress-guard\" all\n"},
		{"wildcard", issue11MainNat + "rdr-anchor \"*\" all\n", issue11MainRules + "anchor \"*\" all\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stubPfctl(t, tc.nat, tc.rules)
			installed, err := (&pfDarwin{}).IsInstalled()
			if !installed || err != nil {
				t.Fatalf("IsInstalled = (%v, %v), want (true, nil)", installed, err)
			}
		})
	}
}

func TestLoadedAnchorWildcardCoversNestedName(t *testing.T) {
	if !loadedAnchorDeclared("rdr-anchor \"foo/*\" all\n", "rdr-anchor", "foo/egress-guard") {
		t.Fatal("foo/* should cover foo/egress-guard")
	}
	if loadedAnchorDeclared("rdr-anchor \"foo/*\" all\n", "rdr-anchor", "egress-guard") {
		t.Fatal("foo/* must not cover top-level egress-guard")
	}
	if loadedAnchorDeclared("# rdr-anchor \"egress-guard\" all\n", "rdr-anchor", "egress-guard") {
		t.Fatal("commented anchor counted")
	}
	if loadedAnchorDeclared("rdr-anchor \"egress/*\" all\n", "rdr-anchor", "egress-guard") {
		t.Fatal("egress/* must not cover egress-guard: a wildcard matches whole path segments")
	}
	if loadedAnchorDeclared("rdr-anchor \"*\" all\n", "rdr-anchor", "foo/egress-guard") {
		t.Fatal("bare * covers top-level anchors only, not foo/egress-guard")
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
