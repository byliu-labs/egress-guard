package allowlist

import "testing"

func TestMatchPattern(t *testing.T) {
	cases := []struct {
		pattern string
		host    string
		want    bool
	}{
		// exact
		{"api.example.com", "api.example.com", true},
		{"api.example.com", "API.EXAMPLE.COM", true}, // case-insensitive
		{"api.example.com", "x.api.example.com", false},
		{"api.example.com", "example.com", false},
		// *. (any subdomain, NOT registered domain itself)
		{"*.github.com", "api.github.com", true},
		{"*.github.com", "objects.githubusercontent.com", false}, // different reg domain
		{"*.github.com", "github.com", false},
		{"*.github.com", "deep.api.github.com", true},
		// **. (registered domain + any subdomain)
		{"**.github.com", "github.com", true},
		{"**.github.com", "api.github.com", true},
		{"**.github.com", "deep.api.github.com", true},
		{"**.github.com", "githubcom", false},
		// trailing dot tolerated
		{"api.example.com", "api.example.com.", true},
		// IDN: caller is responsible for IDN-decoding before match
		{"example.com", "example.com", true},
	}
	for _, c := range cases {
		got := MatchPattern(c.pattern, c.host)
		if got != c.want {
			t.Errorf("MatchPattern(%q, %q) = %v, want %v", c.pattern, c.host, got, c.want)
		}
	}
}

func TestMatchPattern_RejectsBadInput(t *testing.T) {
	bad := []string{"", "*", "**.", "*.com.*", ".example.com", "example..com"}
	for _, p := range bad {
		if MatchPattern(p, "example.com") {
			t.Errorf("MatchPattern(%q, ...) returned true for invalid pattern", p)
		}
	}
}
