package prompt

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// Coalescer wraps a Notifier and (a) reuses decisions for the same registered
// domain within `window`, and (b) detects bursts: when a single pid produces
// more than `burst` distinct registered domains within `window`, all
// subsequent prompts for that pid share a single "process is making many new
// connections" prompt.
//
// Coalescer itself implements Notifier so the CoreDecider can wrap it
// transparently in place of a raw notifier.
type Coalescer struct {
	inner  Notifier
	window time.Duration
	burst  int

	mu          sync.Mutex
	groupByDom  map[string]*group  // regdom → in-flight or last decision
	pidHistory  map[int][]pidEntry // pid → recent (regdom, ts)
	burstByPid  map[int]Action     // pid → cached burst decision
	burstExpiry map[int]time.Time

	innerCalls atomic.Int64
}

type group struct {
	once   sync.Once
	action Action
	err    error
	ready  chan struct{}
	expiry time.Time
}

type pidEntry struct {
	regdom string
	ts     time.Time
}

// burstSafe downgrades the user's burst-prompt response so CoreDecider's
// persist() does not write any user-allowlist rules for domains the user
// did not see in a prompt. The burst dialog shows no specific regdom, so
// translating "Allow always" into "Allow this connection" is the most
// honest thing to do: the user gets through this burst, but every later
// regdom from the same pid still surfaces (or the user explicitly clicks
// "Allow always" on a per-domain prompt later).
func burstSafe(a Action) Action {
	switch a {
	case ActionAllowAlways:
		return ActionAllowOnce
	case ActionDenyAlways:
		return ActionDeny
	default:
		return a
	}
}

// NewCoalescer constructs a Coalescer that groups same-regdom prompts within
// `window` and switches to burst mode when a pid exceeds `burst` distinct
// regdoms inside that window.
func NewCoalescer(inner Notifier, window time.Duration, burst int) *Coalescer {
	return &Coalescer{
		inner:       inner,
		window:      window,
		burst:       burst,
		groupByDom:  map[string]*group{},
		pidHistory:  map[int][]pidEntry{},
		burstByPid:  map[int]Action{},
		burstExpiry: map[int]time.Time{},
	}
}

// InnerCalls returns the number of times the wrapped notifier has been
// invoked. Useful for asserting coalescing behavior in tests.
func (c *Coalescer) InnerCalls() int64 { return c.innerCalls.Load() }

// InBurst reports whether the pid is currently in cached burst mode.
func (c *Coalescer) InBurst(pid int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	exp, ok := c.burstExpiry[pid]
	return ok && time.Now().Before(exp)
}

// Notify implements Notifier. The mutex is released BEFORE any call into the
// inner notifier so a slow user prompt cannot block other goroutines from
// updating coalescer state.
//
// Burst-context responses are downgraded from Always→Once on the way out
// (see burstSafe). The burst dialog body says "process X is making many
// connections" without naming any regdom; if the user clicks "Allow always"
// they're consenting to *this burst*, not to permanently allowlisting every
// regdom involved. Returning the raw Always action would let CoreDecider's
// persist() write `**.{regdom}` for every replay during the burst window,
// silently allowing/denying domains the user never reviewed.
func (c *Coalescer) Notify(ctx context.Context, req Request) (Action, error) {
	now := time.Now()

	// Burst short-circuit: if pid is in burst mode, replay cached action.
	// The cache already holds the burst-safe form (see below), so no further
	// downgrade is needed here.
	c.mu.Lock()
	if exp, ok := c.burstExpiry[req.Proc.PID]; ok && now.Before(exp) {
		a := c.burstByPid[req.Proc.PID]
		c.mu.Unlock()
		return a, nil
	}

	// Update pid history (drop entries outside window).
	hist := c.pidHistory[req.Proc.PID]
	keep := hist[:0]
	for _, e := range hist {
		if now.Sub(e.ts) <= c.window {
			keep = append(keep, e)
		}
	}
	hist = keep

	// Track unique regdoms in the window.
	seen := map[string]bool{}
	for _, e := range hist {
		seen[e.regdom] = true
	}
	if !seen[req.RegDom] {
		hist = append(hist, pidEntry{regdom: req.RegDom, ts: now})
		seen[req.RegDom] = true
	}
	c.pidHistory[req.Proc.PID] = hist

	// Burst trigger: distinct regdoms in window > burst threshold.
	if len(seen) > c.burst {
		c.mu.Unlock()
		c.innerCalls.Add(1)
		burstReq := Request{Proc: req.Proc, Host: "(many)", RegDom: "(burst)", ReceivedAt: now}
		action, err := c.inner.Notify(ctx, burstReq)
		safe := burstSafe(action)
		c.mu.Lock()
		c.burstByPid[req.Proc.PID] = safe
		c.burstExpiry[req.Proc.PID] = now.Add(c.window)
		c.mu.Unlock()
		return safe, err
	}

	// Domain-grouping: same regdom → single decision shared for the window.
	g, ok := c.groupByDom[req.RegDom]
	if ok && now.Before(g.expiry) {
		c.mu.Unlock()
		<-g.ready
		return g.action, g.err
	}
	g = &group{ready: make(chan struct{}), expiry: now.Add(c.window)}
	c.groupByDom[req.RegDom] = g
	c.mu.Unlock()

	c.innerCalls.Add(1)
	a, err := c.inner.Notify(ctx, req)
	g.once.Do(func() {
		g.action = a
		g.err = err
		close(g.ready)
	})
	return a, err
}
