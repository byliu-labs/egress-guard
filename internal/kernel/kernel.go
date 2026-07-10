// Package kernel installs and removes platform-specific rules that redirect
// outbound TCP/443 to the daemon's listener, and recovers the original
// destination of redirected connections. darwin uses pf (rdr anchor +
// DIOCNATLOOK ioctl). Non-darwin builds get an unsupported stub —
// egress-guard's daemon is macOS-only. Linux support returns later as an
// OpenSnitch config-pack rather than a daemon port; see issue #11.
package kernel

import "net"

// RulesInstaller is implemented by pf (darwin) and a stub on non-darwin.
type RulesInstaller interface {
	// Install writes the redirect rules. Idempotent — calling twice does not
	// produce duplicate rules. Requires root privileges.
	Install(redirectPort int) error

	// Uninstall removes any rules previously written by Install. Idempotent.
	Uninstall() error

	// IsInstalled reports whether the redirect rules are currently active.
	IsInstalled() (bool, error)

	// OriginalDest returns the (IP, port) the client was originally trying to
	// reach for the given accepted connection. Implementation depends on
	// platform: SO_ORIGINAL_DST on Linux, DIOCNATLOOK on macOS pf.
	OriginalDest(conn net.Conn) (net.IP, int, error)
}

// Default returns the appropriate installer for the running platform.
func Default() RulesInstaller {
	return defaultInstaller()
}
