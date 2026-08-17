package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/byliu-labs/egress-guard/internal/catalogfetch"
)

// DefaultCatalogURL is where the public baseline catalog is published.
const DefaultCatalogURL = "https://raw.githubusercontent.com/byliu-labs/egress-guard/master/catalog-baseline.toml"

var catalogFetcher catalogfetch.Fetcher = catalogfetch.HTTPFetcher{}

// Catalog implements `egress-guard catalog fetch`: download, verify, validate,
// and install the baseline catalog at baselineCatalogPath().
func Catalog(args []string) error {
	if len(args) == 0 || args[0] != "fetch" {
		return fmt.Errorf("usage: egress-guard catalog fetch [--url <url>] [--pubkey <path>]")
	}
	fs := flag.NewFlagSet("fetch", flag.ContinueOnError)
	url := fs.String("url", DefaultCatalogURL, "catalog URL")
	pubPath := fs.String("pubkey", "", "Ed25519 public key file; overrides the pinned maintainer key for self-hosted catalogs")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	dest, err := baselineCatalogPath()
	if err != nil {
		return err
	}
	pub, err := catalogfetch.MaintainerKey()
	if err != nil {
		return err
	}
	if *pubPath != "" {
		pub, err = os.ReadFile(*pubPath)
		if err != nil {
			return fmt.Errorf("read pubkey: %w", err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := catalogfetch.FetchVerified(ctx, *url, *url+".sig", dest, catalogFetcher, pub); err != nil {
		return fmt.Errorf("%w\n\nThe baseline catalog must be signed by the maintainer. If you are self-hosting a catalog, pass --pubkey <your key file>.", err)
	}
	fmt.Printf("installed baseline catalog: %s\n", dest)
	return nil
}
