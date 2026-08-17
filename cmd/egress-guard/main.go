// cmd/egress-guard/main.go
package main

import (
	"fmt"
	"os"

	"github.com/byliu-labs/egress-guard/internal/cli"
)

const version = "0.2.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	args := os.Args[2:]
	var err error
	switch os.Args[1] {
	case "version", "-v", "--version":
		fmt.Println(version)
		return
	case "install":
		err = cli.Install(args)
	case "enable":
		err = cli.Enable(args)
	case "uninstall":
		err = cli.Uninstall(args)
	case "start":
		err = cli.Start(args)
	case "stop":
		err = cli.Stop(args)
	case "status":
		err = cli.Status(args)
	case "allow":
		err = cli.Allow(args)
	case "deny":
		err = cli.Deny(args)
	case "tail":
		err = cli.Tail(args)
	case "exempt-app":
		err = cli.ExemptApp(args)
	case "telemetry":
		err = cli.Telemetry(args)
	case "catalog":
		err = cli.Catalog(args)
	case "enroll":
		err = cli.Enroll(args)
	case "review":
		err = cli.Review(args)
	default:
		fmt.Fprintf(os.Stderr, "egress-guard: unknown subcommand %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "egress-guard: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `egress-guard [v`+version+`] — egress firewall

Usage:
  egress-guard <command> [args]

Commands (v0.1):
  install       Install kernel rules — pf anchor (requires sudo)
  enable        Install + load the user LaunchAgent (run as user, NOT sudo)
  uninstall     Remove kernel rules (sudo) or LaunchAgent (user) — euid-aware
  start         Start the daemon
  stop          Stop the daemon
  status        Show daemon status
  allow <host>  Add host to allowlist
  deny <host>   Add host to denylist
  tail          Follow the block log
  exempt-app    Manage user-added exempt apps (add/remove/list)
  telemetry     Manage opt-in telemetry (enable/disable/status)
  catalog       Fetch and install a signed public baseline catalog
  enroll        Pin known local tools from the baseline catalog
  review        Review and approve updated pinned binaries
  version       Print version
`)
}
