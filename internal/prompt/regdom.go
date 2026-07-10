package prompt

import "golang.org/x/net/publicsuffix"

// RegisteredDomain returns the eTLD+1 for a hostname. Returns "" for empty
// inputs and the input itself when the public-suffix library can't resolve.
func RegisteredDomain(host string) string {
	if host == "" {
		return ""
	}
	d, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return host
	}
	return d
}
