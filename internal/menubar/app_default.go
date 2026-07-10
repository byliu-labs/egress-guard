//go:build !darwin

package menubar

import "fmt"

// Run is a no-op on non-darwin platforms; the menu bar is macOS-only.
func Run() {
	fmt.Println("egress-guard menu bar is macOS-only")
}
