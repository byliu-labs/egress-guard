package allowlist

import "testing"

func TestAllowlist_BundledDefaults(t *testing.T) {
	a := New(Config{
		Defaults: Layer{Allow: []string{"www.google.com"}},
	})
	got := a.Decide("www.google.com")
	if got != Allow {
		t.Errorf("Decide(www.google.com) = %v, want Allow", got)
	}
}

func TestAllowlist_UnknownDeniesByDefault(t *testing.T) {
	a := New(Config{
		Defaults: Layer{Allow: []string{"www.google.com"}},
	})
	got := a.Decide("evil.example.com")
	if got != Unknown {
		t.Errorf("Decide unknown = %v, want Unknown", got)
	}
}

func TestAllowlist_UserOverridesDefaults(t *testing.T) {
	a := New(Config{
		Defaults: Layer{Allow: []string{"www.google.com"}},
		User:     Layer{Deny: []string{"www.google.com"}},
	})
	got := a.Decide("www.google.com")
	if got != Deny {
		t.Errorf("Decide(www.google.com) with user-deny = %v, want Deny", got)
	}
}

func TestAllowlist_KnownBadOverridesEverything(t *testing.T) {
	a := New(Config{
		KnownBad: Layer{Deny: []string{"models.litellm.cloud"}},
		User:     Layer{Allow: []string{"models.litellm.cloud"}},
	})
	got := a.Decide("models.litellm.cloud")
	if got != Deny {
		t.Errorf("Decide(known-bad) with user-allow = %v, want Deny", got)
	}
}

func TestAllowlist_WildcardMatch(t *testing.T) {
	a := New(Config{
		Defaults: Layer{Allow: []string{"**.github.com"}},
	})
	for _, h := range []string{"github.com", "api.github.com", "objects.githubusercontent.com"} {
		want := Allow
		if h == "objects.githubusercontent.com" {
			want = Unknown // different registered domain: no match → Unknown
		}
		got := a.Decide(h)
		if got != want {
			t.Errorf("Decide(%q) = %v, want %v", h, got, want)
		}
	}
}

func TestDecide_UnmatchedHostReturnsUnknown(t *testing.T) {
	a := New(Config{
		Defaults: Layer{Allow: []string{"github.com"}},
	})
	if got := a.Decide("nowhere.example"); got != Unknown {
		t.Errorf("Decide(unmatched) = %v, want Unknown", got)
	}
	if got := a.Decide("github.com"); got != Allow {
		t.Errorf("Decide(allowed) = %v, want Allow", got)
	}
}

func TestDecide_EmptyHostStillDeny(t *testing.T) {
	a := New(Config{})
	if got := a.Decide(""); got != Deny {
		t.Errorf("Decide(\"\") = %v, want Deny", got)
	}
}

func TestAddUserAllow_LiveMutationVisibleToDecide(t *testing.T) {
	a := New(Config{})
	if got := a.Decide("api.github.com"); got != Unknown {
		t.Fatalf("pre-mutation Decide = %v, want Unknown", got)
	}
	a.AddUserAllow("**.github.com")
	if got := a.Decide("api.github.com"); got != Allow {
		t.Errorf("post-mutation Decide = %v, want Allow", got)
	}
}

func TestAddUserDeny_LiveMutationVisibleToDecide(t *testing.T) {
	a := New(Config{Defaults: Layer{Allow: []string{"**.example.com"}}})
	if got := a.Decide("api.example.com"); got != Allow {
		t.Fatalf("pre-mutation Decide = %v, want Allow (defaults match)", got)
	}
	a.AddUserDeny("**.example.com")
	if got := a.Decide("api.example.com"); got != Deny {
		t.Errorf("post-mutation Decide = %v, want Deny (User.Deny outranks Defaults.Allow)", got)
	}
}

func TestAddUserAllow_Idempotent(t *testing.T) {
	a := New(Config{})
	for range 5 {
		a.AddUserAllow("**.github.com")
	}
	// Force a Deny path by overlaying the same pattern in User.Deny — the
	// dedup is observable by checking we don't accidentally duplicate.
	// Simpler check: build a second allowlist seeded with our cfg snapshot
	// and verify length 1.
	a.mu.RLock()
	n := len(a.cfg.User.Allow)
	a.mu.RUnlock()
	if n != 1 {
		t.Errorf("User.Allow length = %d, want 1 (idempotent)", n)
	}
}
