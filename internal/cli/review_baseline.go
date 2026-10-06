package cli

import (
	"fmt"
	"io"
	"time"

	"github.com/byliu-labs/egress-guard/internal/drift"
	"github.com/byliu-labs/egress-guard/internal/rejected"
)

// defaultReviewWindow is a view default, independent of the learning warm-up.
const defaultReviewWindow = 7 * 24 * time.Hour

func reviewKey(p drift.LearnedPair) rejected.Key {
	return rejected.Key{ExeBasename: p.Identity.ExeBasename, ExeSHA256: p.Identity.ExeSHA256, TeamID: p.Identity.TeamID, Host: p.Host}
}
func renderBaselineReview(w io.Writer, pairs []drift.LearnedPair) {
	if len(pairs) == 0 {
		fmt.Fprintln(w, "Nothing learned in this view.")
		return
	}
	for i, p := range pairs {
		fmt.Fprintf(w, "%d. %q -> %q\n   first seen %s; last %s; %d connections\n", i+1, p.Identity.ExeBasename, p.Host, p.FirstSeen.Format("2006-01-02 15:04"), p.LastSeen.Format("2006-01-02 15:04"), p.Count)
	}
}
func rejectByIndex(store *rejected.Store, pairs []drift.LearnedPair, n int, why string) error {
	if n < 1 || n > len(pairs) {
		return fmt.Errorf("review: item %d out of range (1..%d)", n, len(pairs))
	}
	return store.Reject(reviewKey(pairs[n-1]), why)
}
func renderRejected(w io.Writer, records []rejected.Record) {
	if len(records) == 0 {
		fmt.Fprintln(w, "Nothing rejected.")
		return
	}
	for i, r := range records {
		fmt.Fprintf(w, "%d. %q -> %q; rejected %s; reason %q\n", i+1, r.Key.ExeBasename, r.Key.Host, r.At.Format("2006-01-02 15:04"), r.Why)
	}
}
func reviewBaseline(store *rejected.Store, since int) ([]drift.LearnedPair, error) {
	logPath, err := reviewLogPath()
	if err != nil {
		return nil, err
	}
	cachePath, err := baselineCachePath()
	if err != nil {
		return nil, err
	}
	b, err := loadOrBuildBaseline(logPath, cachePath, nil, nil, rejectionAdapter{s: store})
	if err != nil {
		return nil, err
	}
	if since > 0 {
		return b.LearnedSince(time.Now().Add(-time.Duration(since) * 24 * time.Hour)), nil
	}
	return b.Learned(), nil
}
