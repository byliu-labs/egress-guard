// cmd/catalog-build compiles the public catalog/ fragments into distributable
// known-good catalog artifacts.
package main

import (
	"crypto/ed25519"
	"flag"
	"fmt"
	"os"

	"github.com/byliu-labs/egress-guard/internal/catalogbuild"
	"github.com/byliu-labs/egress-guard/internal/catalogsig"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "catalog-build: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: catalog-build build|refresh|embed-exempt|keygen|sign [flags]")
	}
	switch args[0] {
	case "build", "refresh":
		return cmdBuild(args[1:])
	case "embed-exempt":
		return cmdEmbedExempt(args[1:])
	case "keygen":
		return cmdKeygen(args[1:])
	case "sign":
		return cmdSign(args[1:])
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

func cmdKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	pubOut := fs.String("pub-out", "catalog-baseline.pub", "public key output path")
	privOut := fs.String("priv-out", "", "private key output path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *privOut == "" {
		return fmt.Errorf("keygen requires --priv-out; keep this file secret and out of git")
	}
	pub, priv, err := catalogsig.GenerateKey()
	if err != nil {
		return err
	}
	if err := writeNewFile(*pubOut, pub, 0o644); err != nil {
		return err
	}
	if err := writeNewFile(*privOut, priv, 0o600); err != nil {
		return err
	}
	fmt.Printf("wrote %s and %s\n", *pubOut, *privOut)
	return nil
}

func cmdSign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	catalogPath := fs.String("catalog", "catalog-baseline.toml", "compiled catalog path")
	privPath := fs.String("private-key", "", "Ed25519 private key path")
	sigOut := fs.String("sig-out", "catalog-baseline.toml.sig", "signature output path")
	pubOut := fs.String("pub-out", "", "optional public key output path derived from the private key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *privPath == "" {
		return fmt.Errorf("sign requires --private-key")
	}
	data, err := os.ReadFile(*catalogPath)
	if err != nil {
		return fmt.Errorf("read catalog %s: %w", *catalogPath, err)
	}
	priv, err := os.ReadFile(*privPath)
	if err != nil {
		return fmt.Errorf("read private key %s: %w", *privPath, err)
	}
	sig, err := catalogsig.Sign(data, priv)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*sigOut, sig, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", *sigOut, err)
	}
	if *pubOut != "" {
		pub := ed25519.PrivateKey(priv).Public().(ed25519.PublicKey)
		if err := os.WriteFile(*pubOut, pub, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", *pubOut, err)
		}
	}
	fmt.Printf("wrote %s (%d bytes)\n", *sigOut, len(sig))
	return nil
}

func writeNewFile(path string, b []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer f.Close()
	if _, err := f.Write(b); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
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
