//go:build !darwin

package cli

import (
	"fmt"
	"io"
)

func printPlatformStatus(w io.Writer) error {
	_, err := fmt.Fprintln(w, "egress-guard daemon: unsupported platform (macOS-only; see issue #11 for Linux via OpenSnitch)")
	return err
}
