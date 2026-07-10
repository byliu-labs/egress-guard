//go:build !darwin

package cli

import "errors"

// installLaunchAgent / uninstallLaunchAgent are darwin-only — egress-guard
// is a macOS-first daemon. Linux support will return as an OpenSnitch
// config-pack, not a daemon port (see issue #11). Non-darwin builds get a
// stub that errors out instead of silently no-op'ing.

func installLaunchAgent(port int) error {
	return errors.New("egress-guard daemon is macOS-only; see issue #11 for Linux via OpenSnitch")
}

func uninstallLaunchAgent() error {
	return errors.New("egress-guard daemon is macOS-only; see issue #11 for Linux via OpenSnitch")
}
