package daemon

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/decisionlog"
	"github.com/byliu-labs/egress-guard/internal/drift"
	"github.com/byliu-labs/egress-guard/internal/procid"
	"github.com/byliu-labs/egress-guard/internal/signature"
)

func newDaemonForBaselineTest() *Daemon {
	return &Daemon{lastSeen: newLastSeen(maxLiveLastSeenPairs)}
}

type recordingDaemonLogger struct{ messages []string }

func (l *recordingDaemonLogger) Errorf(format string, args ...any) {
	l.messages = append(l.messages, fmt.Sprintf(format, args...))
}

// TestDaemon_SetBaseline_RaceFreeWithClassify drives many concurrent
// classifyDrift readers against a writer swapping the baseline, and must be
// race-clean under `go test -race`. This is the high-risk concurrency gate:
// a plain *drift.Baseline field would race here.
func TestDaemon_SetBaseline_RaceFreeWithClassify(t *testing.T) {
	d := newDaemonForBaselineTest()
	d.SetBaseline(drift.BuildBaseline(nil, nil))

	var wg sync.WaitGroup
	stop := make(chan struct{})

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = d.classifyDrift(
						"example.com",
						procid.ProcInfo{Exe: "/usr/bin/x", PID: 1},
						signature.SignedIdentity{},
						catalog.Identity{ExeBasename: "x"},
					)
				}
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 2000; i++ {
			d.SetBaseline(drift.BuildBaseline(nil, nil))
		}
		close(stop)
	}()

	wg.Wait()
}

func TestDaemon_SetBaselineKeepsLastSeenPointer(t *testing.T) {
	d := newDaemonForBaselineTest()
	before := d.lastSeen
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				d.lastSeen.at("test-pair")
			}
		}
	}()
	for i := 0; i < 2000; i++ {
		d.SetBaseline(drift.BuildBaseline(nil, nil))
	}
	close(stop)
	wg.Wait()
	if d.lastSeen != before {
		t.Fatal("SetBaseline replaced the live lastSeen state")
	}
}

// TestDaemon_SetBaselineRequiresConstructorInitialisedLastSeen pins the
// deletion of SetBaseline's nil-guard. Pointer identity cannot do it: every
// test daemon is built with a non-nil lastSeen, so the guard's branch is dead
// and re-adding it verbatim leaves the whole suite green. The guard's absence
// is observable only as a panic on a bare &Daemon{}.
func TestDaemon_SetBaselineRequiresConstructorInitialisedLastSeen(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("SetBaseline tolerated a nil lastSeen: the nil-guard is back, and with it a plain pointer write racing every connection goroutine")
		}
	}()
	(&Daemon{}).SetBaseline(drift.BuildBaseline(nil, nil))
}

func TestDaemon_SetBaselineLogsLiveEvictions(t *testing.T) {
	logger := &recordingDaemonLogger{}
	d := newDaemonForBaselineTest()
	d.opts.Logger = logger
	entries := make([]decisionlog.Entry, 4097)
	base := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	for i := range entries {
		entries[i] = decisionlog.Entry{
			Timestamp: base.Add(time.Duration(i) * time.Second).Format(time.RFC3339),
			Decision:  decisionlog.DecisionAllow,
			Exe:       "/usr/bin/curl",
			Host:      "host-" + strconv.Itoa(i) + ".example",
		}
	}
	baseline := drift.BuildBaseline(&catalog.Catalog{}, entries)
	d.SetBaseline(baseline)
	if len(logger.messages) != 1 {
		t.Fatalf("logger messages = %v, want exactly one eviction message", logger.messages)
	}
	if !strings.Contains(logger.messages[0], "baseline over by 1 pair(s)") {
		t.Fatalf("logger message = %q, want the amount the cap was exceeded by", logger.messages[0])
	}
	// Nothing was live before the first seed, so nothing can have been evicted.
	// Counting declined historical pairs here would report a stable live set as
	// though it were churning.
	if !strings.Contains(logger.messages[0], "0 live reference(s) dropped this refresh") {
		t.Fatalf("logger message = %q, want zero live references dropped when the map started empty", logger.messages[0])
	}
	if got := d.lastSeen.evictionCount(); got != 0 {
		t.Fatalf("evictionCount = %d after seeding an empty map, want 0: no live reference existed to evict", got)
	}
	// A baseline larger than the cap keeps reporting cap pressure on every
	// refresh, so a second line is correct. What must NOT happen is the
	// PER-REFRESH cost growing: that is the tell that the running total is
	// being reported as this refresh's cost, which turns one steady-state
	// condition into an alarm that inflates forever. The lifetime total is
	// allowed to move — it is a different number, labelled as such — so the
	// comparison is scoped to the text before it.
	d.SetBaseline(baseline)
	if len(logger.messages) != 2 {
		t.Fatalf("logger messages = %v, want one line per over-capacity refresh", logger.messages)
	}
	perRefresh := func(message string) string {
		lifetime := strings.Index(message, " since start")
		if lifetime < 0 {
			t.Fatalf("logger message = %q, want a lifetime total", message)
		}
		cut := strings.LastIndex(message[:lifetime], ", ")
		if cut < 0 {
			t.Fatalf("logger message = %q, want a per-refresh cost before the lifetime total", message)
		}
		return message[:cut]
	}
	if perRefresh(logger.messages[0]) != perRefresh(logger.messages[1]) {
		t.Fatalf("per-refresh eviction report grew across refreshes:\n  %q\n  %q", logger.messages[0], logger.messages[1])
	}

	// A baseline that fits must be silent, or the line means nothing.
	quiet := &recordingDaemonLogger{}
	fits := newDaemonForBaselineTest()
	fits.opts.Logger = quiet
	fits.SetBaseline(drift.BuildBaseline(&catalog.Catalog{}, entries[:8]))
	if len(quiet.messages) != 0 {
		t.Fatalf("under-capacity SetBaseline logged %v, want silence", quiet.messages)
	}
}

func TestDaemon_SetBaselineDoesNotRollLiveLastSeenBack(t *testing.T) {
	entry := decisionlog.Entry{
		Timestamp: "2026-08-19T12:00:00Z", Decision: decisionlog.DecisionAllow,
		Exe: "/usr/bin/curl", Host: "allow.example",
	}
	baseline := drift.BuildBaseline(&catalog.Catalog{}, []decisionlog.Entry{entry})
	d := newDaemonForBaselineTest()
	d.SetBaseline(baseline)
	key := drift.BaselinePairKey(entry)
	live := time.Date(2026, 8, 19, 12, 30, 0, 0, time.UTC)
	d.lastSeen.advance(key, live)
	d.SetBaseline(baseline)
	if got := d.lastSeen.at(key); !got.Equal(live) {
		t.Fatalf("SetBaseline rolled live reference back to %v", got)
	}
}

// TestDaemon_SetBaseline_NilStaysGeneric verifies a daemon with no baseline set
// still classifies (generic novel pairing), preserving pre-wiring behavior.
func TestDaemon_SetBaseline_NilStaysGeneric(t *testing.T) {
	d := newDaemonForBaselineTest()
	ev := d.classifyDrift("example.com",
		procid.ProcInfo{Exe: "/usr/bin/x", PID: 1},
		signature.SignedIdentity{},
		catalog.Identity{ExeBasename: "x"})
	if ev.Class != drift.ClassDrift || ev.Reason != drift.ReasonNovelPairing {
		t.Fatalf("nil baseline: got class=%q reason=%q, want drift/novel_pairing", ev.Class, ev.Reason)
	}
}

// TestDaemon_SetBaselineReportsLiveEvictionsTheBaselineDidNotCause pins the
// independence of the two quantities SetBaseline reports. overCap measures the
// snapshot against the cap; evicted measures live references actually lost.
// Gating the operator line on overCap alone makes the worse case the silent
// one: a baseline that fits can still displace every live reference, and that
// is exactly what happens when the log the baseline is rebuilt from is missing
// pairs the live map holds — Log.Write errors are discarded (decision.go), so
// an unwritable state volume produces precisely this shape.
func TestDaemon_SetBaselineReportsLiveEvictionsTheBaselineDidNotCause(t *testing.T) {
	logger := &recordingDaemonLogger{}
	d := newDaemonForBaselineTest()
	d.opts.Logger = logger

	// Fill the live map exactly to capacity with pairs the baseline will not
	// mention, all older than anything in it.
	live := time.Date(2026, 8, 19, 9, 0, 0, 0, time.UTC)
	for i := 0; i < maxLiveLastSeenPairs; i++ {
		d.lastSeen.advance("live-"+strconv.Itoa(i), live.Add(time.Duration(i)*time.Second))
	}

	// A baseline of exactly maxLiveLastSeenPairs newer pairs: it fits the cap
	// (overCap == 0) yet displaces every live reference.
	entries := make([]decisionlog.Entry, maxLiveLastSeenPairs)
	base := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	for i := range entries {
		entries[i] = decisionlog.Entry{
			Timestamp: base.Add(time.Duration(i) * time.Second).Format(time.RFC3339),
			Decision:  decisionlog.DecisionAllow,
			Exe:       "/usr/bin/curl",
			Host:      "fresh-" + strconv.Itoa(i) + ".example",
		}
	}
	d.SetBaseline(drift.BuildBaseline(&catalog.Catalog{}, entries))

	if got := d.lastSeen.evictionCount(); got == 0 {
		t.Fatal("evictionCount = 0: the fixture is wrong, no live reference was displaced")
	}
	if len(logger.messages) != 1 {
		t.Fatalf("logger messages = %v, want one line: %d live reference(s) were dropped and the operator was told nothing",
			logger.messages, d.lastSeen.evictionCount())
	}
}

// TestDaemon_SetBaselineReportsLifetimeEvictions keeps the lifetime counter
// wired to something an operator can see. evictLocked also increments it from
// the connection path, so it carries churn between refreshes that seed's
// per-refresh return value never observes; unreported, that churn is invisible.
//
// The refreshes must carry disjoint pairs. Reseeding one over-capacity baseline
// is idempotent after the rebuild — seed keeps the same newest max, evicts
// nothing, and the lifetime total correctly stays put. Live references are lost
// only when a refresh brings pairs that outrank the ones already held.
func TestDaemon_SetBaselineReportsLifetimeEvictions(t *testing.T) {
	logger := &recordingDaemonLogger{}
	d := newDaemonForBaselineTest()
	d.opts.Logger = logger

	base := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	overCapacityAt := func(prefix string, at time.Time) *drift.Baseline {
		entries := make([]decisionlog.Entry, maxLiveLastSeenPairs+1)
		for i := range entries {
			entries[i] = decisionlog.Entry{
				Timestamp: at.Add(time.Duration(i) * time.Second).Format(time.RFC3339),
				Decision:  decisionlog.DecisionAllow,
				Exe:       "/usr/bin/curl",
				Host:      prefix + "-" + strconv.Itoa(i) + ".example",
			}
		}
		return drift.BuildBaseline(&catalog.Catalog{}, entries)
	}

	d.SetBaseline(overCapacityAt("first", base))
	d.SetBaseline(overCapacityAt("second", base.Add(24*time.Hour)))

	if len(logger.messages) != 2 {
		t.Fatalf("logger messages = %v, want one line per over-capacity refresh", logger.messages)
	}
	want := "since start"
	for i, message := range logger.messages {
		if !strings.Contains(message, want) {
			t.Fatalf("message[%d] = %q, want a lifetime total (%q): without it the counter has no production reader and its accumulation is deletable",
				i, message, want)
		}
	}
	if logger.messages[0] == logger.messages[1] {
		t.Fatalf("lifetime total did not move across two refreshes that displaced every live reference; both lines read %q", logger.messages[0])
	}
}
