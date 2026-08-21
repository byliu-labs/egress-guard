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
	if !strings.Contains(logger.messages[0], "exceeds the 4096-pair live cap by 1 pair(s)") {
		t.Fatalf("logger message = %q, want the amount the cap was exceeded by", logger.messages[0])
	}
	// Nothing was live before the first seed, so nothing can have been evicted.
	// Counting declined historical pairs here would report a stable live set as
	// though it were churning.
	if !strings.Contains(logger.messages[0], "(0 live reference(s) dropped this refresh)") {
		t.Fatalf("logger message = %q, want zero live references dropped when the map started empty", logger.messages[0])
	}
	if got := d.lastSeen.evictionCount(); got != 0 {
		t.Fatalf("evictionCount = %d after seeding an empty map, want 0: no live reference existed to evict", got)
	}
	// A baseline larger than the cap really does evict on every refresh, so a
	// second line is correct. What must NOT happen is the number growing: that
	// is the tell that the running total is being reported as this refresh's
	// cost, which turns one steady-state condition into an alarm that inflates
	// forever.
	d.SetBaseline(baseline)
	if len(logger.messages) != 2 {
		t.Fatalf("logger messages = %v, want one line per over-capacity refresh", logger.messages)
	}
	if logger.messages[0] != logger.messages[1] {
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
