package explain

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
)

// Config is the BYO endpoint and key for the live explainer. There is no
// compiled-in default endpoint or key.
type Config struct {
	Endpoint  string
	APIKey    string
	Model     string
	LocalOnly bool
}

// ErrNotConfigured means no endpoint is set, so no explainer is available.
var ErrNotConfigured = errors.New("explain: no endpoint configured (set EGRESS_GUARD_EXPLAIN_ENDPOINT)")

const (
	envEndpoint  = "EGRESS_GUARD_EXPLAIN_ENDPOINT"
	envAPIKey    = "EGRESS_GUARD_EXPLAIN_API_KEY"
	envModel     = "EGRESS_GUARD_EXPLAIN_MODEL"
	envLocalOnly = "EGRESS_GUARD_EXPLAIN_LOCAL"
)

// ConfigFromEnv reads the BYO endpoint/key from the environment.
func ConfigFromEnv() (Config, error) {
	endpoint := os.Getenv(envEndpoint)
	if endpoint == "" {
		return Config{}, ErrNotConfigured
	}
	cfg := Config{
		Endpoint:  endpoint,
		APIKey:    os.Getenv(envAPIKey),
		Model:     os.Getenv(envModel),
		LocalOnly: isTruthy(os.Getenv(envLocalOnly)),
	}
	if !cfg.LocalOnly && cfg.APIKey == "" {
		return Config{}, fmt.Errorf("explain: %s is set without %s (API mode requires a key; set %s=1 for local model mode)", envEndpoint, envAPIKey, envLocalOnly)
	}
	if err := validateEndpointSecurity(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func validateEndpointSecurity(cfg Config) error {
	u, err := url.Parse(cfg.Endpoint)
	if err != nil {
		return fmt.Errorf("explain: invalid endpoint %q: %w", cfg.Endpoint, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("explain: endpoint %q must be an absolute URL", cfg.Endpoint)
	}
	if !cfg.LocalOnly && u.Scheme != "https" {
		return fmt.Errorf("explain: API mode requires https endpoint before sending bearer credentials (got %q)", u.Scheme)
	}
	return nil
}

func isTruthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
