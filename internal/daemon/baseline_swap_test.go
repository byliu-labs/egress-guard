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
	// Anchored on both separators: an unanchored "0 live reference(s)" is a
	// substring of every non-zero count ending in 0.
	if !strings.Contains(logger.messages[0], "pair(s), 0 live reference(s) dropped this refresh, ") {
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
	// Both figures pinned on a refresh that displaces the whole live map, which
	// is the case the sibling test cannot cover: there the reporting refresh
	// evicts nothing of its own, so the lifetime total is identical whether it
	// is read before or after the seed. Here they are equal and non-zero, which
	// is only true if the lifetime figure is read AFTER the seed.
	n := strconv.Itoa(maxLiveLastSeenPairs)
	want := "pair(s), " + n + " live reference(s) dropped this refresh, " + n + " since start)"
	if !strings.Contains(logger.messages[0], want) {
		t.Fatalf("message = %q,\n want it to contain %q.\n A lifetime total read before the seed omits exactly this refresh's drops, and the log line is the counter's only production reader.",
			logger.messages[0], want)
	}
}

// TestDaemon_SetBaselineReportsLifetimeEvictions keeps the lifetime counter
// wired to something an operator can see. evictLocked also increments it from
// the connection path, so it carries churn between refreshes that seed's
// per-refresh return value never observes; unreported, that churn is invisible.
//
// The churn therefore has to come from advance, not from seed. An earlier
// version of this test drove both refreshes through seed, so the lifetime total
// and the per-refresh count moved together (0/0 then 4096/4096) and no
// assertion could tell them apart — reporting uint64(evicted) in place of
// evictionCount() left the whole suite green. Here the second refresh evicts
// nothing itself while 100 live references have already been dropped by the
// connection path, so the two numbers are forced apart.
func TestDaemon_SetBaselineReportsLifetimeEvictions(t *testing.T) {
	logger := &recordingDaemonLogger{}
	d := newDaemonForBaselineTest()
	d.opts.Logger = logger

	entries := make([]decisionlog.Entry, maxLiveLastSeenPairs+1)
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
	if got := d.lastSeen.evictionCount(); got != 0 {
		t.Fatalf("evictionCount = %d after the first seed of an empty map, want 0", got)
	}

	// The connection path drops 100 live references. The map is already at
	// capacity, so each new pair evicts exactly one.
	const churn = 100
	for i := 0; i < churn; i++ {
		d.lastSeen.advance("connection-"+strconv.Itoa(i), base.Add(time.Duration(10000+i)*time.Second))
	}
	if got := d.lastSeen.evictionCount(); got != churn {
		t.Fatalf("evictionCount = %d after %d connection-path evictions, want %d: the fixture is wrong", got, churn, churn)
	}

	d.SetBaseline(baseline)
	if len(logger.messages) != 2 {
		t.Fatalf("logger messages = %v, want one line per over-capacity refresh", logger.messages)
	}
	// This refresh drops nothing of its own: the pairs the cap displaces are the
	// ones the connection path already evicted, so they are no longer live.
	//
	// Both figures are anchored in ONE substring, with the separators included.
	// Checking them apart lets a substring match through — "100 live
	// reference(s) dropped this refresh" contains "0 live reference(s) dropped
	// this refresh", so printing the lifetime total in the per-refresh slot
	// satisfies a bare Contains for zero.
	want := "pair(s), 0 live reference(s) dropped this refresh, " + strconv.Itoa(churn) + " since start)"
	if !strings.Contains(logger.messages[1], want) {
		t.Fatalf("message[1] = %q,\n want it to contain %q.\n This refresh displaced nothing and the connection path displaced %d; swapping either figure for the other hides one of them.",
			logger.messages[1], want, churn)
	}
}

// TestDaemon_SetBaselineNilIsSilent covers the boot path taken when the
// decision log will not parse: loadOrBuildBaseline returns nil and New hands it
// straight to SetBaseline with the production logger already wired. Nothing had
// exercised it, so a nil baseline reporting cap pressure would print an alarm
// at startup on exactly the machine whose log is already broken.
func TestDaemon_SetBaselineNilIsSilent(t *testing.T) {
	logger := &recordingDaemonLogger{}
	d := newDaemonForBaselineTest()
	d.opts.Logger = logger
	d.SetBaseline(nil)
	if len(logger.messages) != 0 {
		t.Fatalf("SetBaseline(nil) logged %v, want silence: there is no baseline, so there is no cap pressure to report", logger.messages)
	}
}
