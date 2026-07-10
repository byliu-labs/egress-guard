package config

import (
	"strings"
	"testing"
)

func TestLoadDefaultsEmbedded(t *testing.T) {
	c, err := LoadDefaults()
	if err != nil {
		t.Fatalf("LoadDefaults: %v", err)
	}
	if len(c.Allow) < 5 {
		t.Errorf("expected at least 5 default allow entries, got %d", len(c.Allow))
	}
	hasGithub := false
	for _, h := range c.Allow {
		if h == "github.com" {
			hasGithub = true
			break
		}
	}
	if !hasGithub {
		t.Error("expected github.com in defaults")
	}
}

func TestLoadFromString(t *testing.T) {
	in := `
[allow]
hosts = ["example.com", "*.foo.com"]
[deny]
hosts = ["evil.com"]
`
	c, err := LoadFromString(in)
	if err != nil {
		t.Fatalf("LoadFromString: %v", err)
	}
	if len(c.Allow) != 2 || c.Allow[0] != "example.com" {
		t.Errorf("Allow = %v, want [example.com *.foo.com]", c.Allow)
	}
	if len(c.Deny) != 1 || c.Deny[0] != "evil.com" {
		t.Errorf("Deny = %v, want [evil.com]", c.Deny)
	}
}

func TestLoadFromString_InvalidTOML(t *testing.T) {
	_, err := LoadFromString(`this is not toml ===`)
	if err == nil {
		t.Error("expected error for invalid TOML")
	}
	if !strings.Contains(err.Error(), "config:") {
		t.Errorf("error should be wrapped with package prefix: %v", err)
	}
}
