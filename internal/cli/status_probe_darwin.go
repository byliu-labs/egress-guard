//go:build darwin

package cli

import (
	"errors"
	"os"
	"time"

	"github.com/byliu-labs/egress-guard/internal/decisionlog"
	"github.com/byliu-labs/egress-guard/internal/drift"
	"github.com/byliu-labs/egress-guard/internal/pending"
	"github.com/byliu-labs/egress-guard/internal/rejected"
)

// StatusReport is the structured, root-free view of egress-guard's launchd +
// routing state. It powers both the CLI status output and the menu-bar glyph.
// It intentionally omits kernel-anchor state, which requires root to read.
type StatusReport struct {
	AgentLoaded           bool
	DaemonPID             int
	BootDaemonLoaded      bool
	BootDaemonPID         int
	BootDaemonDisabled    bool
	BootDaemonUnknown     bool
	TUNIface              string
	PendingReviews        int
	BaselinePendingReview int
}

// Probe gathers launchd + default-route state. It shells out only to
// user-runnable commands (launchctl, route), so it never needs sudo.
func Probe() StatusReport {
	agent := checkAgent()
	boot := checkDaemonJob()
	iface := defaultRouteInterface()
	if !isTUNInterface(iface) {
		iface = ""
	}
	pendingReviews := 0
	if p, err := configPath("pending-reviews.jsonl"); err == nil {
		if n, err := pending.Count(p); err == nil {
			pendingReviews = n
		}
	}
	baselinePending := 0
	if p, err := RejectedPairsPath(); err == nil {
		if store, err := rejected.Open(p); err == nil {
			baselinePending = baselineReviewCount(store, time.Now())
		}
	}
	return StatusReport{
		AgentLoaded:           agent.Loaded,
		DaemonPID:             agent.PID,
		BootDaemonLoaded:      boot.Loaded,
		BootDaemonPID:         boot.PID,
		BootDaemonDisabled:    boot.Disabled,
		BootDaemonUnknown:     boot.Unknown,
		TUNIface:              iface,
		PendingReviews:        pendingReviews,
		BaselinePendingReview: baselinePending,
	}
}

func baselineReviewCount(store *rejected.Store, now time.Time) int {
	logPath, err := reviewLogPath()
	if err != nil {
		return 0
	}
	cachePath, err := baselineCachePath()
	if err != nil {
		return 0
	}
	if store.Quarantined() {
		return 0
	}
	entries, err := decisionlog.ReadHistory(logPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return 0
	}
	baseline, err := drift.LoadBaseline(cachePath, nil)
	if err != nil || baseline.IsStale(entries) || baseline.RejectionDigest() != store.Digest() {
		baseline = drift.BuildBaselineWithRejections(nil, entries, rejectionAdapter{s: store})
	}
	if baseline == nil {
		return 0
	}
	return len(baseline.LearnedSince(now.Add(-defaultReviewWindow)))
}
