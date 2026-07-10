//go:build !darwin

package kernel

import (
	"errors"
	"net"
)

// unsupported is the catch-all installer for non-darwin builds. egress-guard's
// kernel-redirect path (pf rdr → DIOCNATLOOK) is macOS-only. The Linux daemon
// port (nftables + SO_ORIGINAL_DST) was deprioritized; Linux support returns
// as an OpenSnitch config-pack — see issue #11.
type unsupported struct{}

var errUnsupportedPlatform = errors.New("kernel: macOS-only; see issue #11 for Linux via OpenSnitch")

func defaultInstaller() RulesInstaller { return unsupported{} }

func (unsupported) Install(int) error                        { return errUnsupportedPlatform }
func (unsupported) Uninstall() error                         { return errUnsupportedPlatform }
func (unsupported) IsInstalled() (bool, error)               { return false, errUnsupportedPlatform }
func (unsupported) OriginalDest(net.Conn) (net.IP, int, error) {
	return nil, 0, errUnsupportedPlatform
}
