package cli

import (
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/pending"
	"github.com/byliu-labs/egress-guard/internal/prompt"
)

// Review lists or approves binaries that changed under a ratified pin.
func Review(args []string) error {
	fs := flag.NewFlagSet("review", flag.ContinueOnError)
	approve := fs.Bool("approve-all", false, "pin every queued binary and clear the queue")
	if err := fs.Parse(args); err != nil {
		return err
	}

	path, err := configPath("pending-reviews.jsonl")
	if err != nil {
		return err
	}
	store, err := pending.Open(path)
	if err != nil {
		return err
	}
	items, err := store.List()
	if err != nil {
		return err
	}
	if len(items) == 0 {
		fmt.Println("Nothing to review.")
		return nil
	}

	fmt.Printf("%d binaries changed since you pinned them:\n\n", len(items))
	for _, it := range items {
		fmt.Printf("  %-8s %s\n           was %s\n           now %s\n           used for: %s (%d connections since %s)\n\n",
			it.Basename, it.ExePath,
			shortHash(it.OldSHA256), shortHash(it.NewSHA256),
			strings.Join(it.Hosts, ", "), it.Count, it.FirstSeen.Format("2006-01-02 15:04"))
	}
	if !*approve {
		fmt.Println("Run `egress-guard review --approve-all` to pin these, or inspect them first.")
		return nil
	}

	catalogPath, err := userCatalogPath()
	if err != nil {
		return err
	}
	if err := approveAll(store, newCatalogRatifyWriter(catalogPath, nil)); err != nil {
		return err
	}
	fmt.Print(reviewPinnedMessage(len(items)))
	return nil
}

func reviewPinnedMessage(n int) string {
	return fmt.Sprintf("Pinned %d updated binaries. Restart the daemon for these pins to take effect.\n", n)
}

func approveAll(store *pending.Store, w prompt.RatifyWriter) error {
	items, err := store.List()
	if err != nil {
		return err
	}
	for _, it := range items {
		for _, h := range it.Hosts {
			e := catalog.Entry{
				SchemaVersion:        catalog.CurrentSchemaVersion,
				Identity:             catalog.Identity{ExeBasename: it.Basename, ExePath: it.ExePath, ExeSHA256: it.NewSHA256},
				ExpectedDestinations: []catalog.Destination{{Host: h, Why: "approved at review"}},
				Explanation:          fmt.Sprintf("%s was updated and re-approved by the user.", it.Basename),
				Evidence:             fmt.Sprintf("reviewed %s: %s -> %s", time.Now().Format("2006-01-02"), shortHash(it.OldSHA256), shortHash(it.NewSHA256)),
				Confidence:           catalog.ConfidenceMedium,
				Layer:                "user",
			}
			if err := w.Ratify(e); err != nil {
				return fmt.Errorf("review: pin %s: %w", it.Basename, err)
			}
		}
		if err := store.Resolve(it.ExePath, it.NewSHA256); err != nil {
			return err
		}
	}
	return nil
}

func shortHash(s string) string {
	if len(s) < 12 {
		return s
	}
	return s[:12]
}
