package cli

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/pending"
	"github.com/byliu-labs/egress-guard/internal/prompt"
	"github.com/byliu-labs/egress-guard/internal/rejected"
)

// Review is the one place to inspect learned pairs and changed binaries.
func Review(args []string) error {
	fs := flag.NewFlagSet("review", flag.ContinueOnError)
	approve := fs.Bool("approve-all", false, "pin every queued binary and clear the queue")
	baseline := fs.Bool("baseline", false, "show every learned baseline pair")
	rejectedList := fs.Bool("rejected", false, "show rejected baseline pairs")
	since := fs.Int("since", 0, "with --baseline, show pairs first seen in the last N days")
	reject := fs.Int("reject", 0, "reject learned pair N")
	restore := fs.Int("restore", 0, "restore rejected pair N")
	why := fs.String("why", "", "reason for rejection")
	dismiss := fs.Int("dismiss", 0, "dismiss changed binary N without pinning")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *since < 0 {
		return fmt.Errorf("review: --since must be nonnegative")
	}
	if *reject < 0 || *restore < 0 || *dismiss < 0 {
		return fmt.Errorf("review: item numbers must be positive")
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
	if *dismiss > 0 {
		if *dismiss > len(items) {
			return fmt.Errorf("review: binary %d out of range", *dismiss)
		}
		it := items[*dismiss-1]
		if err := store.Resolve(it.ExePath, it.NewSHA256); err != nil {
			return err
		}
		fmt.Printf("Dismissed binary %d.\n", *dismiss)
		return nil
	}
	if *approve {
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
	rejectionPath, err := RejectedPairsPath()
	if err != nil {
		return err
	}
	rejections, err := rejected.Open(rejectionPath)
	if err != nil {
		return err
	}
	if *rejectedList || *restore > 0 {
		records := rejections.List()
		if *restore > 0 {
			if *restore > len(records) {
				return fmt.Errorf("review: rejected item %d out of range", *restore)
			}
			if err := rejections.Restore(records[*restore-1].Key); err != nil {
				return err
			}
			fmt.Printf("Restored rejected pair %d; restart or refresh the daemon.\n", *restore)
			return nil
		}
		renderRejected(os.Stdout, records)
		return nil
	}
	if *baseline || *reject > 0 {
		pairs, err := reviewBaseline(rejections, *since)
		if err != nil {
			return err
		}
		if *reject > 0 {
			if err := rejectByIndex(rejections, pairs, *reject, *why); err != nil {
				return err
			}
			fmt.Printf("Rejected pair %d; restart or refresh the daemon. This does not deny traffic.\n", *reject)
			return nil
		}
		renderBaselineReview(os.Stdout, pairs)
		return nil
	}
	if len(items) == 0 {
		fmt.Println("No changed binaries to review.")
	} else {
		fmt.Printf("%d binaries changed since you pinned them:\n\n", len(items))
		for i, it := range items {
			fmt.Printf("%d. %q %q\n   was %s; now %s; used for: %q (%d connections since %s)\n", i+1, it.Basename, it.ExePath, shortHash(it.OldSHA256), shortHash(it.NewSHA256), strings.Join(it.Hosts, ", "), it.Count, it.FirstSeen.Format("2006-01-02 15:04"))
		}
		fmt.Println("Use --approve-all to pin all or --dismiss N to remove one.")
	}
	pairs, err := reviewBaseline(rejections, int(defaultReviewWindow/(24*time.Hour)))
	if err != nil {
		return err
	}
	fmt.Printf("%d recently learned baseline pairs. Run `egress-guard review --baseline` to inspect all.\n", len(pairs))
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
