// nebridge-proto serves Network Extension filter decisions over a Unix socket.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/byliu-labs/egress-guard/internal/allowlist"
	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/config"
	"github.com/byliu-labs/egress-guard/internal/daemon"
	"github.com/byliu-labs/egress-guard/internal/decisionlog"
	"github.com/byliu-labs/egress-guard/internal/kernel"
	"github.com/byliu-labs/egress-guard/internal/nebridge"
	"github.com/byliu-labs/egress-guard/internal/signature"
)

const defaultSocket = "/tmp/egress-guard-nefilter.sock"

func main() {
	if err := run(os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

func run(args []string) error {
	flags := flag.NewFlagSet("nebridge-proto", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	socketPath := flags.String("socket", defaultSocket, "Unix socket path")
	allowlistPath := flags.String("allowlist", "", "allowlist TOML path")
	logPath := flags.String("log", "", "decision log path")
	observeOnly := flags.Bool("observe", false, "log decisions without enforcing drops")
	testStubIdentity := flags.Bool("test-stub-identity", false, "")
	flags.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: nebridge-proto -allowlist <path> -log <path> [flags]")
		fmt.Fprintln(os.Stderr, "  -socket <path>")
		fmt.Fprintln(os.Stderr, "  -observe")
	}
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *allowlistPath == "" {
		return errors.New("nebridge-proto: -allowlist is required")
	}
	if *logPath == "" {
		return errors.New("nebridge-proto: -log is required")
	}

	defaults, err := config.LoadDefaults()
	if err != nil {
		return fmt.Errorf("nebridge-proto: load default allowlist: %w", err)
	}
	user, err := config.LoadFromFile(*allowlistPath)
	if err != nil {
		return fmt.Errorf("nebridge-proto: load allowlist: %w", err)
	}
	allow := allowlist.New(allowlist.Config{
		Defaults: allowlist.Layer{Allow: defaults.Allow, Deny: defaults.Deny},
		User:     allowlist.Layer{Allow: user.Allow, Deny: user.Deny},
	})

	decisionLog, err := decisionlog.Open(*logPath)
	if err != nil {
		return fmt.Errorf("nebridge-proto: open decision log: %w", err)
	}
	defer decisionLog.Close()

	decider, err := daemon.New(daemon.Options{
		Kernel:      kernel.Default(),
		Allow:       allow,
		Log:         decisionLog,
		Catalog:     &catalog.Catalog{},
		ObserveOnly: *observeOnly,
	})
	if err != nil {
		return fmt.Errorf("nebridge-proto: create daemon: %w", err)
	}

	resolver := nebridge.NewSystemResolver(signature.Default())
	if *testStubIdentity {
		resolver = nebridge.StubResolver{}
	}
	listener, err := nebridge.Listen(*socketPath)
	if err != nil {
		return err
	}
	defer listener.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return (&nebridge.Server{Decider: decider, Resolver: resolver, Log: decisionLog}).Serve(ctx, listener)
}
