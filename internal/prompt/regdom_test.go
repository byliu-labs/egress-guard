package prompt

import "testing"

func TestRegisteredDomain(t *testing.T) {
	cases := map[string]string{
		"a.s3.amazonaws.com":   "a.s3.amazonaws.com",
		"foo.bar.github.io":    "bar.github.io",
		"github.com":           "github.com",
		"":                     "",
		"localhost":            "localhost",
		"some.api.openai.com":  "openai.com",
	}
	for in, want := range cases {
		if got := RegisteredDomain(in); got != want {
			t.Errorf("RegisteredDomain(%q) = %q, want %q", in, got, want)
		}
	}
}
