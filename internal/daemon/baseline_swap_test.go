package daemon

import (
	"sync"
	"testing"

	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/drift"
	"github.com/byliu-labs/egress-guard/internal/procid"
	"github.com/byliu-labs/egress-guard/internal/signature"
)

// TestDaemon_SetBaseline_RaceFreeWithClassify drives many concurrent
// classifyDrift readers against a writer swapping the baseline, and must be
// race-clean under `go test -race`. This is the high-risk concurrency gate:
// a plain *drift.Baseline field would race here.
func TestDaemon_SetBaseline_RaceFreeWithClassify(t *testing.T) {
	d := &Daemon{}
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

// TestDaemon_SetBaseline_NilStaysGeneric verifies a daemon with no baseline set
// still classifies (generic novel pairing), preserving pre-wiring behavior.
func TestDaemon_SetBaseline_NilStaysGeneric(t *testing.T) {
	d := &Daemon{}
	ev := d.classifyDrift("example.com",
		procid.ProcInfo{Exe: "/usr/bin/x", PID: 1},
		signature.SignedIdentity{},
		catalog.Identity{ExeBasename: "x"})
	if ev.Class != drift.ClassDrift || ev.Reason != drift.ReasonNovelPairing {
		t.Fatalf("nil baseline: got class=%q reason=%q, want drift/novel_pairing", ev.Class, ev.Reason)
	}
}
