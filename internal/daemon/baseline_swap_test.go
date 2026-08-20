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
				before.at("test-pair")
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
	d.SetBaseline(drift.BuildBaseline(&catalog.Catalog{}, entries))
	if len(logger.messages) != 1 {
		t.Fatalf("logger messages = %v, want exactly one eviction message", logger.messages)
	}
	if !strings.Contains(logger.messages[0], "evicted") {
		t.Fatalf("logger message = %q, want eviction context", logger.messages[0])
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
