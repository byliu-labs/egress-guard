// Package daemon hosts the SNI-filtering TCP proxy. The daemon is given a
// platform kernel installer (for original-dst recovery), an allowlist, and a
// decision log; it accepts redirected connections, decides allow/deny/observe,
// and either splices or closes.
package daemon

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/byliu-labs/egress-guard/internal/allowlist"
	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/decisionlog"
	"github.com/byliu-labs/egress-guard/internal/drift"
	"github.com/byliu-labs/egress-guard/internal/exempt"
	"github.com/byliu-labs/egress-guard/internal/explain"
	"github.com/byliu-labs/egress-guard/internal/kernel"
	"github.com/byliu-labs/egress-guard/internal/pending"
	"github.com/byliu-labs/egress-guard/internal/procid"
	"github.com/byliu-labs/egress-guard/internal/prompt"
	"github.com/byliu-labs/egress-guard/internal/signature"
)

// PendingRecorder records upgraded binaries that are allowed under narrow
// stale-pin grace and need later user review.
type PendingRecorder interface {
	Record(pending.Item) error
}

type pendingHashCounter interface {
	DistinctNewHashes(exePath string) (int, error)
}

// IdleReporter reports whether a human was recently at the keyboard.
// It is observational only: errors and nil omit the field from the log.
type IdleReporter interface {
	Active() (bool, error)
}

// Options bundles the daemon's runtime dependencies.
type Options struct {
	Listen string
	Kernel kernel.RulesInstaller
	Allow  *allowlist.Allowlist
	Log    *decisionlog.Writer

	// v0.2 additions. Nil means "v0.1 behavior preserved" (deny on Unknown).
	ProcID    procid.Lookup
	Signature signature.Verifier
	Exempt    *exempt.Catalog
	Prompt    prompt.Decider

	// Binder, when non-nil, requires an allowed connection's destination IP to
	// be one the allowed hostname actually resolves to — closing the
	// SNI-spoofing bypass where a client names an allowlisted host while
	// connecting to an attacker IP. Nil = SNI string trusted alone (the
	// original, spoofable behavior).
	Binder DestBinder

	// Catalog is consulted before prompting: authoritative expected
	// destinations allow silently, prompt-only matches explain the prompt, and
	// Never hits deny silently.
	Catalog *catalog.Catalog

	// Baseline enriches prompt requests with the drift reason. Nil keeps
	// correctness and reports unknown traffic as generic novel pairing.
	Baseline *drift.Baseline

	// Explainer, when non-nil, produces an advisory model opinion for an
	// unknown identity/host before the user is prompted. Nil = no opinion
	// (req.Opinion stays nil, preserving pre-wiring behavior). The call is
	// bounded by explainTimeout and fails open: a slow, hung, or erroring
	// explainer never delays admission beyond the bound, never blocks the
	// prompt from rendering, and never influences the allow/deny verdict.
	Explainer explain.Explainer

	// Logger surfaces background explainer failures. Nil drops them silently.
	Logger explain.Logger

	// Pending receives stale-binary grace observations. Grace is not granted
	// unless the observation is recorded.
	Pending PendingRecorder

	// Idle stamps decision entries with presence metadata and never influences
	// an allow or deny verdict.
	Idle IdleReporter

	// ObserveOnly puts the daemon in shadow mode: policy verdicts are logged
	// as Decision=observe but not enforced. Entry.Action keeps the shadow
	// allow/deny verdict for later drift analysis.
	ObserveOnly bool
}

// DestBinder verifies that a destination IP is legitimate for a hostname.
// Implemented by *dnsbind.Binder; an interface here so tests can stub it.
type DestBinder interface {
	DestMatches(host string, ip net.IP) (bool, error)
}

// Daemon is the running listener.
type Daemon struct {
	opts     Options
	listener net.Listener
	ready    chan struct{}
	dial     func(network, address string) (net.Conn, error)
	now      func() time.Time
	mu       sync.Mutex
	hasher   *procid.ExeHasher
	inflight *inflight
	// lastSeen is written once in New and read from every connection goroutine;
	// SetBaseline must never replace it after construction.
	lastSeen *lastSeen
	// onCompletedScore is an in-memory observer for completed-flow scoring.
	// Production leaves it nil; it never affects admission or persistence.
	onCompletedScore func(drift.Event)
	// baseline is the drift baseline the decision path consults. It is an
	// atomic pointer (not opts.Baseline directly) so a background refresher can
	// swap it while connection goroutines read it without a data race. A nil
	// pointer is valid and degrades to generic novel-pairing classification.
	baseline atomic.Pointer[drift.Baseline]
}

func (d *Daemon) nowTime() time.Time {
	if d.now != nil {
		return d.now()
	}
	return timeNow()
}

// New creates a daemon. Call Run to start.
func New(opts Options) (*Daemon, error) {
	if opts.Allow == nil || opts.Log == nil || opts.Kernel == nil {
		return nil, errors.New("daemon: Options missing required field")
	}
	d := &Daemon{
		opts: opts, ready: make(chan struct{}), dial: net.Dial,
		hasher: procid.NewExeHasher(), inflight: newInflight(),
		lastSeen: newLastSeen(maxLiveLastSeenPairs),
	}
	d.SetBaseline(opts.Baseline) // may be nil; atomic.Pointer handles it
	return d, nil
}

// SetBaseline atomically swaps the drift baseline the decision path consults.
// Safe to call from a background refresher while connection goroutines classify.
// The baseline is observe-only enrichment: swapping it never changes allow/deny.
func (d *Daemon) SetBaseline(b *drift.Baseline) {
	evicted, overCap := d.lastSeen.seed(b)
	if overCap > 0 && d.opts.Logger != nil {
		d.opts.Logger.Errorf("drift: baseline exceeds the %d-pair live cap by %d pair(s) (%d live reference(s) dropped this refresh); the calibrator replay is unbounded, so thresholds derived from it no longer apply above the cap",
			maxLiveLastSeenPairs, overCap, evicted)
	}
	d.baseline.Store(b)
}

// Run starts the listener and serves connections until ctx is cancelled.
func (d *Daemon) Run(ctx context.Context) error {
	ln, err := net.Listen("tcp", d.opts.Listen)
	if err != nil {
		return err
	}
	d.mu.Lock()
	d.listener = ln
	d.mu.Unlock()
	close(d.ready)

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		c, err := ln.Accept()
		if err != nil {
			return nil
		}
		go d.handle(c)
	}
}

// WaitListen blocks until the daemon is listening, then returns its address.
func (d *Daemon) WaitListen() net.Addr {
	<-d.ready
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.listener.Addr()
}

// clientHelloDeadline bounds how long we'll wait for the ClientHello.
const clientHelloDeadline = 5 * time.Second
