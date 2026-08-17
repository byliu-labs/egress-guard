// Package prompt implements the v0.2 user-prompt subsystem: a Decider that
// queues up unknown-host connections, asks the user via a platform notifier,
// and returns Allow/Deny within a deadline (default-deny on timeout).
package prompt

import (
	"context"
	"time"

	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/drift"
	"github.com/byliu-labs/egress-guard/internal/explain"
	"github.com/byliu-labs/egress-guard/internal/persist"
	"github.com/byliu-labs/egress-guard/internal/procid"
)

// Action is the user's choice in response to a prompt.
type Action int

const (
	ActionDeny Action = iota
	ActionAllow
	ActionAllowOnce
	ActionAllowAlways
	ActionDenyAlways
)

// Request is one connection awaiting a verdict.
type Request struct {
	Proc       procid.ProcInfo
	Host       string
	RegDom     string // registered domain (eTLD+1)
	ReceivedAt time.Time

	// Drift-prompt context. Zero values mean "context unavailable" and must
	// never imply an allow decision.
	CatalogMatch catalog.MatchResult
	Drift        drift.Event
	Opinion      *explain.Explanation
	Persistence  *persist.Source
}

// Decision is the verdict returned to the daemon.
type Decision int

const (
	Allow Decision = iota
	Deny
)

// Notifier is the platform-specific surface; the stub returns timeout-deny.
type Notifier interface {
	Notify(ctx context.Context, req Request) (Action, error)
}

// Decider answers Allow/Deny for unknown-host connections.
type Decider interface {
	Decide(ctx context.Context, req Request) Decision
}

// Options bundles the Decider's runtime config.
type Options struct {
	Notifier     Notifier
	Timeout      time.Duration // default 30s; ActionDeny on expiry
	AlwaysWriter AlwaysWriter  // optional: persists Allow/Deny-Always to user config
	// RatifyWriter supersedes AlwaysWriter for AllowAlways/DenyAlways when
	// configured, persisting identity+destination catalog facts instead of
	// bare registered-domain strings.
	RatifyWriter RatifyWriter
	// Logger is called on persistence failures (AlwaysWriter rejecting
	// AddAllow or AddDeny). Nil means errors are silently dropped (v0.1
	// behavior); cli.Start wires log.Default() so failures surface.
	Logger Logger
}

// Logger is a minimal interface for surfacing background errors. Satisfied
// by a thin adapter over the stdlib log package.
type Logger interface {
	Errorf(format string, args ...any)
}

// AlwaysWriter persists the user's Allow-Always / Deny-Always choices.
// Implementations append a wildcard pattern (e.g. `**.example.com`) to the
// user allow/deny config file AND update the live allowlist so the next
// connection from any process to the same registered domain is auto-decided
// without re-prompting.
//
// The argument is the registered domain (eTLD+1), not the exact host the
// user saw in the dialog. Picking "Allow always" for `api.github.com`
// allows the whole `github.com` family — matches what the prompt body says
// and the granularity the burst coalescer already groups by.
type AlwaysWriter interface {
	AddAllow(regdom string) error
	AddDeny(regdom string) error
}

// CoreDecider is the reference implementation. The decider itself is
// stateless — persistence (Allow-Always / Deny-Always) goes through
// AlwaysWriter, and rate-limiting comes from the user-allowlist matching
// in the daemon's allowlist layer (no in-memory cache here, by design).
type CoreDecider struct {
	opts Options
}

func New(opts Options) *CoreDecider {
	if opts.Timeout == 0 {
		opts.Timeout = 30 * time.Second
	}
	return &CoreDecider{opts: opts}
}

// Decide blocks until the user answers or the deadline expires. Default on
// timeout = Deny.
func (c *CoreDecider) Decide(ctx context.Context, req Request) Decision {
	subCtx, cancel := context.WithTimeout(ctx, c.opts.Timeout)
	defer cancel()
	action, err := c.opts.Notifier.Notify(subCtx, req)
	if err != nil {
		return Deny
	}
	d := actionToDecision(action)
	c.persist(action, req)
	return d
}

func actionToDecision(a Action) Decision {
	switch a {
	case ActionAllow, ActionAllowOnce, ActionAllowAlways:
		return Allow
	default:
		return Deny
	}
}

func (c *CoreDecider) persist(a Action, req Request) {
	switch a {
	case ActionAllowAlways:
		c.persistAlways(req, true)
	case ActionDenyAlways:
		c.persistAlways(req, false)
	}
}

func (c *CoreDecider) persistAlways(req Request, allow bool) {
	if c.opts.RatifyWriter != nil {
		entry := catalogEntryFor(req, allow)
		if err := c.opts.RatifyWriter.Ratify(entry); err != nil {
			if c.opts.Logger != nil {
				c.opts.Logger.Errorf("prompt: Ratify(%q, allow=%v) failed: %v", req.RegDom, allow, err)
			}
			return
		}
		if allow && !catalog.HasDecisionPin(entry.Identity) && c.opts.Logger != nil {
			c.opts.Logger.Errorf("prompt: Ratify(%q, allow=true) stored context-only entry without identity pin; future connections still require prompt", req.RegDom)
		}
		return
	}
	if c.opts.AlwaysWriter == nil {
		return
	}
	var err error
	verb := "AddDeny"
	if allow {
		verb = "AddAllow"
		err = c.opts.AlwaysWriter.AddAllow(req.RegDom)
	} else {
		err = c.opts.AlwaysWriter.AddDeny(req.RegDom)
	}
	if err != nil && c.opts.Logger != nil {
		c.opts.Logger.Errorf("prompt: %s(%q) failed: %v", verb, req.RegDom, err)
	}
}
