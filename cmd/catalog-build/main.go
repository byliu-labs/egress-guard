// cmd/catalog-build compiles the public catalog/ fragments into distributable
// known-good catalog artifacts.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/byliu-labs/egress-guard/internal/catalogbuild"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "catalog-build: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: catalog-build build|refresh|embed-exempt [flags]")
	}
	switch args[0] {
	case "build", "refresh":
		return cmdBuild(args[1:])
	case "embed-exempt":
		return cmdEmbedExempt(args[1:])
	default:
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

func cmdBuild(args []string) error {
	fs := flag.NewFlagSet("build", flag.ContinueOnError)
	baseline := fs.String("baseline", "catalog/baseline", "baseline fragment dir")
	out := fs.String("out", "catalog-baseline.toml", "output path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, err := catalogbuild.LoadBaselineDir(*baseline)
	if err != nil {
		return err
	}
	b, err := catalogbuild.CompileBaseline(c)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, b, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", *out, err)
	}
	fmt.Printf("wrote %s (%d bytes)\n", *out, len(b))
	return nil
}

func cmdEmbedExempt(args []string) error {
	fs := flag.NewFlagSet("embed-exempt", flag.ContinueOnError)
	exemptDir := fs.String("exempt", "catalog/exempt", "exempt fragment dir")
	out := fs.String("out", "internal/exempt/defaults_embedded.toml", "output path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	b, err := catalogbuild.CompileExempt(*exemptDir)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, b, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", *out, err)
	}
	fmt.Printf("wrote %s (%d bytes)\n", *out, len(b))
	return nil
}
