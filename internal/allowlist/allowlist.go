package allowlist

import "sync"

// Decision is the daemon's filter verdict for a single hostname.
type Decision int

const (
	Allow Decision = iota
	Deny
	Unknown
)

func (d Decision) String() string {
	switch d {
	case Allow:
		return "allow"
	case Deny:
		return "deny"
	case Unknown:
		return "unknown"
	}
	return "invalid"
}

// Layer is one slice of allow/deny patterns. A layer can have both lists; deny
// wins within a layer (defense against accidental allow-shadows-deny config).
type Layer struct {
	Allow []string
	Deny  []string
}

// Config holds the layered configuration. Resolution order, most specific first:
//  1. KnownBad   — deny always wins regardless of what else allows
//  2. User       — user-global allowlist + denylist
//  3. Defaults   — bundled defaults (from configs/defaults.toml)
//
// v0.1 omits the per-project layer; v0.3 will add it.
type Config struct {
	KnownBad Layer
	User     Layer
	Defaults Layer
}

// Allowlist makes filter decisions. Construct with New; safe for concurrent
// reads and writes (the prompt subsystem's "Allow always"/"Deny always"
// actions append patterns at runtime via AddUserAllow/AddUserDeny).
type Allowlist struct {
	mu  sync.RWMutex
	cfg Config
}

// New returns an Allowlist seeded by the given config.
func New(cfg Config) *Allowlist {
	return &Allowlist{cfg: cfg}
}

// Decide returns the verdict for a hostname. Empty hostname is denied.
func (a *Allowlist) Decide(host string) Decision {
	if host == "" {
		return Deny
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	// 1. KnownBad: any deny match → Deny.
	if anyMatch(a.cfg.KnownBad.Deny, host) {
		return Deny
	}
	// 2. User layer: deny first, then allow.
	if anyMatch(a.cfg.User.Deny, host) {
		return Deny
	}
	if anyMatch(a.cfg.User.Allow, host) {
		return Allow
	}
	// 3. Defaults layer.
	if anyMatch(a.cfg.Defaults.Deny, host) {
		return Deny
	}
	if anyMatch(a.cfg.Defaults.Allow, host) {
		return Allow
	}
	// No layer matched → Unknown. Caller decides what to do (v0.2: prompt).
	return Unknown
}

// AddUserAllow appends a pattern to the user Allow layer at runtime.
// Idempotent — duplicates are dropped. Used by the prompt subsystem's
// "Allow always" action so the next connection to the same domain is
// auto-allowed without re-prompting.
func (a *Allowlist) AddUserAllow(pattern string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !containsString(a.cfg.User.Allow, pattern) {
		a.cfg.User.Allow = append(a.cfg.User.Allow, pattern)
	}
}

// AddUserDeny is the Deny-side counterpart to AddUserAllow.
func (a *Allowlist) AddUserDeny(pattern string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !containsString(a.cfg.User.Deny, pattern) {
		a.cfg.User.Deny = append(a.cfg.User.Deny, pattern)
	}
}

func containsString(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func anyMatch(patterns []string, host string) bool {
	for _, p := range patterns {
		if MatchPattern(p, host) {
			return true
		}
	}
	return false
}
