package explain_test

import (
	"errors"
	"testing"

	"github.com/byliu-labs/egress-guard/internal/explain"
)

func TestConfigFromEnv_NotConfigured(t *testing.T) {
	t.Setenv("EGRESS_GUARD_EXPLAIN_ENDPOINT", "")
	_, err := explain.ConfigFromEnv()
	if !errors.Is(err, explain.ErrNotConfigured) {
		t.Fatalf("want ErrNotConfigured, got %v", err)
	}
}

func TestConfigFromEnv_APIModeRequiresKey(t *testing.T) {
	t.Setenv("EGRESS_GUARD_EXPLAIN_ENDPOINT", "https://api.example.com/v1/chat/completions")
	t.Setenv("EGRESS_GUARD_EXPLAIN_API_KEY", "")
	t.Setenv("EGRESS_GUARD_EXPLAIN_LOCAL", "")
	_, err := explain.ConfigFromEnv()
	if err == nil {
		t.Fatal("want an error: API mode requires a user-supplied key")
	}
}

func TestConfigFromEnv_APIModeRequiresHTTPS(t *testing.T) {
	t.Setenv("EGRESS_GUARD_EXPLAIN_ENDPOINT", "http://api.example.com/v1/chat/completions")
	t.Setenv("EGRESS_GUARD_EXPLAIN_API_KEY", "user-supplied-test-key")
	t.Setenv("EGRESS_GUARD_EXPLAIN_LOCAL", "")
	_, err := explain.ConfigFromEnv()
	if err == nil {
		t.Fatal("API mode must reject plaintext HTTP before bearer credentials can be sent")
	}
}

func TestConfigFromEnv_LocalOptInNeedsNoKey(t *testing.T) {
	t.Setenv("EGRESS_GUARD_EXPLAIN_ENDPOINT", "http://localhost:11434/v1/chat/completions")
	t.Setenv("EGRESS_GUARD_EXPLAIN_API_KEY", "")
	t.Setenv("EGRESS_GUARD_EXPLAIN_LOCAL", "1")
	cfg, err := explain.ConfigFromEnv()
	if err != nil {
		t.Fatalf("local opt-in should not require a key: %v", err)
	}
	if !cfg.LocalOnly {
		t.Fatal("expected LocalOnly=true")
	}
}

func TestConfigFromEnv_FullAPIConfig(t *testing.T) {
	t.Setenv("EGRESS_GUARD_EXPLAIN_ENDPOINT", "https://api.example.com/v1/chat/completions")
	t.Setenv("EGRESS_GUARD_EXPLAIN_API_KEY", "user-supplied-test-key")
	t.Setenv("EGRESS_GUARD_EXPLAIN_MODEL", "gpt-test")
	t.Setenv("EGRESS_GUARD_EXPLAIN_LOCAL", "")
	cfg, err := explain.ConfigFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Endpoint == "" || cfg.APIKey == "" || cfg.Model == "" {
		t.Fatalf("expected all fields populated from env, got %+v", cfg)
	}
}
