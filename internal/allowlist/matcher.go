package allowlist

import "strings"

// MatchPattern reports whether host matches pattern. Patterns are case-insensitive
// and support these forms:
//   - exact:    "api.example.com"
//   - subdomain wildcard:        "*.example.com"  (matches a.example.com but NOT example.com)
//   - registered + subdomains:   "**.example.com" (matches example.com AND any subdomain)
//
// Hostnames may have a trailing dot (FQDN form); both pattern and host are
// normalized by stripping trailing dots and lowercasing before comparison.
//
// Patterns must contain at least one dot, must not start with a dot, and
// wildcards must occupy the leftmost label only.
func MatchPattern(pattern, host string) bool {
	p := normalize(pattern)
	h := normalize(host)
	if !validPattern(p) {
		return false
	}
	if h == "" {
		return false
	}
	switch {
	case strings.HasPrefix(p, "**."):
		base := p[3:]
		return h == base || strings.HasSuffix(h, "."+base)
	case strings.HasPrefix(p, "*."):
		base := p[2:]
		return strings.HasSuffix(h, "."+base) && h != base
	default:
		return p == h
	}
}

func normalize(s string) string {
	s = strings.TrimSuffix(s, ".")
	return strings.ToLower(s)
}

func validPattern(p string) bool {
	if p == "" {
		return false
	}
	if strings.HasPrefix(p, ".") || strings.HasSuffix(p, ".") {
		return false
	}
	if strings.Contains(p, "..") {
		return false
	}
	rest := p
	if strings.HasPrefix(rest, "**.") {
		rest = rest[3:]
	} else if strings.HasPrefix(rest, "*.") {
		rest = rest[2:]
	}
	if !strings.Contains(rest, ".") {
		return false
	}
	if strings.ContainsAny(rest, "*") {
		return false
	}
	return true
}
