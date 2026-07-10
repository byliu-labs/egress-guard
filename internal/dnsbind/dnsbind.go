// Package dnsbind binds an allow-by-SNI decision to the connection's real
// destination IP. A hostname allowlist that trusts the client-supplied SNI
// alone is bypassed by any malicious client that names an allowlisted host
// while connecting to an attacker IP (see
// internal/daemon/sni_spoof_poc_test.go). Requiring the destination IP to be
// one the hostname actually resolves to closes that spoof.
//
// This raises the attacker's bar from "spoof one string" to "control the
// hostname's DNS or reuse an allowlisted shared IP". It does NOT stop exfil to
// a genuinely allowlisted destination (a gist, an attacker-owned S3 bucket) —
// that is inherent to destination-allowlisting and out of this package's scope.
package dnsbind

import (
	"context"
	"net"
	"sync"
	"time"
)

// Resolver is the subset of *net.Resolver dnsbind needs. Abstracted so tests
// (and the daemon's own tests) can supply deterministic answers without real
// DNS.
type Resolver interface {
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
}

// Binder answers "does host legitimately resolve to ip?" with a short forward
// cache to absorb per-connection cost and modest CDN churn.
type Binder struct {
	res     Resolver
	ttl     time.Duration
	timeout time.Duration

	mu    sync.Mutex
	cache map[string]cacheEntry
}

type cacheEntry struct {
	ips map[string]struct{}
	at  time.Time
}

// New returns a Binder backed by the system resolver.
func New() *Binder { return NewWithResolver(net.DefaultResolver) }

// NewWithResolver returns a Binder backed by a caller-supplied resolver.
func NewWithResolver(r Resolver) *Binder {
	return &Binder{
		res:     r,
		ttl:     60 * time.Second,
		timeout: 2 * time.Second,
		cache:   make(map[string]cacheEntry),
	}
}

// DestMatches reports whether ip is among host's currently-resolvable
// addresses. A non-nil error means resolution failed and the caller must decide
// the posture (the daemon fails closed: unverifiable → deny).
func (b *Binder) DestMatches(host string, ip net.IP) (bool, error) {
	set, err := b.resolve(host)
	if err != nil {
		return false, err
	}
	_, ok := set[ip.String()]
	return ok, nil
}

func (b *Binder) resolve(host string) (map[string]struct{}, error) {
	b.mu.Lock()
	if e, ok := b.cache[host]; ok && time.Since(e.at) < b.ttl {
		b.mu.Unlock()
		return e.ips, nil
	}
	b.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), b.timeout)
	defer cancel()
	addrs, err := b.res.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	set := make(map[string]struct{}, len(addrs))
	for _, a := range addrs {
		set[a.String()] = struct{}{}
	}
	b.mu.Lock()
	b.cache[host] = cacheEntry{ips: set, at: time.Now()}
	b.mu.Unlock()
	return set, nil
}
