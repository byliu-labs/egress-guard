package cli

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/byliu-labs/egress-guard/internal/catalogfetch"
)

// DefaultCatalogURL is where the public baseline catalog is published.
const DefaultCatalogURL = "https://raw.githubusercontent.com/byliu-labs/egress-guard/master/catalog-baseline.toml"

// Catalog implements `egress-guard catalog fetch`: download, verify, validate,
// and install the baseline catalog at baselineCatalogPath().
func Catalog(args []string) error {
	if len(args) == 0 || args[0] != "fetch" {
		return fmt.Errorf("usage: egress-guard catalog fetch [--url <url>] --pubkey <path>")
	}
	fs := flag.NewFlagSet("fetch", flag.ContinueOnError)
	url := fs.String("url", DefaultCatalogURL, "catalog URL")
	pubPath := fs.String("pubkey", "", "required Ed25519 public key file; verifies <url>.sig before install")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *pubPath == "" {
		return fmt.Errorf("catalog fetch requires --pubkey; unsigned remote baseline installs are refused")
	}
	dest, err := baselineCatalogPath()
	if err != nil {
		return err
	}
	ctx := context.Background()
	pub, err := os.ReadFile(*pubPath)
	if err != nil {
		return fmt.Errorf("read pubkey: %w", err)
	}
	if err := catalogfetch.FetchVerified(ctx, *url, *url+".sig", dest, catalogfetch.HTTPFetcher{}, pub); err != nil {
		return err
	}
	fmt.Printf("installed baseline catalog: %s\n", dest)
	return nil
}
