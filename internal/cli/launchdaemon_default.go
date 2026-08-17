//go:build !darwin

package cli

import "errors"

func installLaunchDaemon(port int) error {
	return errors.New("egress-guard daemon is macOS-only; see issue #11 for Linux via OpenSnitch")
}

func uninstallLaunchDaemon() error {
	return errors.New("egress-guard daemon is macOS-only; see issue #11 for Linux via OpenSnitch")
}

func systemBaselineCatalogPath() (string, error) {
	return "", errors.New("catalog fetch --system is macOS-only")
}

func BootDaemonInstalled() bool {
	return launchDaemonInstalled()
}

var launchDaemonInstalled = func() bool { return false }
