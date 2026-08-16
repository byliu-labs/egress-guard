// cmd/catalog-build compiles the public catalog/ fragments into distributable
// known-good catalog artifacts.
package main

import (
	"bytes"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/byliu-labs/egress-guard/internal/catalog"
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
		return fmt.Errorf("usage: catalog-build build|refresh|embed-exempt|genkey|sign [flags]")
	}
	switch args[0] {
	case "build", "refresh":
		return cmdBuild(args[1:])
	case "embed-exempt":
		return cmdEmbedExempt(args[1:])
	case "genkey":
		return cmdGenKey(args[1:])
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
	b, err := compileBaselineForOutput(c, *out)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, b, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", *out, err)
	}
	fmt.Printf("wrote %s (%d bytes)\n", *out, len(b))
	return nil
}

func compileBaselineForOutput(c *catalog.Catalog, out string) ([]byte, error) {
	existingBytes, readErr := os.ReadFile(out)
	if readErr == nil {
		existing, err := catalog.Load(existingBytes)
		if err == nil && existing.IssuedAt() != "" {
			c.SetIssuedAt(existing.IssuedAt())
			candidate, err := c.Marshal()
			if err == nil && bytes.Equal(candidate, existingBytes) {
				return candidate, nil
			}
			c.SetIssuedAt("")
		}
	}
	b, err := catalogbuild.CompileBaseline(c)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func cmdGenKey(args []string) error {
	fs := flag.NewFlagSet("genkey", flag.ContinueOnError)
	pubOut := fs.String("pub-out", "internal/catalogfetch/maintainer.pub", "public key output path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	pub, priv, err := catalogsig.GenerateKey()
	if err != nil {
		return err
	}
	if err := writeNewFile(*pubOut, pub, 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s (commit this)\n", *pubOut)
	fmt.Println("Store this private key in CATALOG_SIGNING_KEY; it is printed once:")
	fmt.Println(base64.StdEncoding.EncodeToString(priv))
	return nil
}

func cmdSign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	in := fs.String("in", "catalog-baseline.toml", "artifact to sign")
	key := fs.String("key", "", "file holding the base64 Ed25519 private key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	priv, err := signingKey(*key)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(*in)
	if err != nil {
		return fmt.Errorf("read %s: %w", *in, err)
	}
	sig, err := catalogsig.Sign(data, priv)
	if err != nil {
		return err
	}
	out := *in + ".sig"
	if err := os.WriteFile(out, sig, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", out, err)
	}
	fmt.Printf("wrote %s (%d bytes)\n", out, len(sig))
	return nil
}

func signingKey(path string) ([]byte, error) {
	var encoded string
	if path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read signing key %s: %w", path, err)
		}
		encoded = string(raw)
	} else {
		encoded = os.Getenv("CATALOG_SIGNING_KEY")
	}
	encoded = strings.TrimSpace(encoded)
	if encoded == "" {
		return nil, fmt.Errorf("no signing key: pass --key <file> or set CATALOG_SIGNING_KEY")
	}
	priv, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("signing key is not valid base64: %w", err)
	}
	return priv, nil
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
