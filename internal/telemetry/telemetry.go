// Package telemetry implements opt-in, anonymous, minimal-field intake of
// user ratifications. It is off unless a user explicitly enables it.
package telemetry

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
	"github.com/byliu-labs/egress-guard/internal/catalog"
)

// Report is the exact wire payload sent to the maintainer review queue.
type Report struct {
	InstallUUID   string
	Identity      catalog.Identity
	Host          string
	Verdict       string
	SchemaVersion int
}

const reportSchemaVersion = 1

// NewReport builds a Report ready to send, stamped with the current schema.
func NewReport(installUUID string, id catalog.Identity, host, verdict string) Report {
	return Report{
		InstallUUID:   installUUID,
		Identity:      id,
		Host:          host,
		Verdict:       verdict,
		SchemaVersion: reportSchemaVersion,
	}
}

// Config is the user's local opt-in toggle plus stable anonymous install ID.
type Config struct {
	Enabled     bool   `toml:"enabled"`
	InstallUUID string `toml:"install_uuid"`
	Endpoint    string `toml:"endpoint"`
}

// DefaultEndpoint is the maintainer-run review queue intake.
const DefaultEndpoint = "https://telemetry.egress-guard.dev/v1/report"

// LoadConfig reads path. Missing config means telemetry has never been enabled.
func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &Config{Enabled: false}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("telemetry: read %s: %w", path, err)
	}
	var cfg Config
	if _, err := toml.Decode(string(b), &cfg); err != nil {
		return nil, fmt.Errorf("telemetry: parse %s: %w", path, err)
	}
	return &cfg, nil
}

// SaveConfig writes cfg to path, creating parent directories as needed.
func SaveConfig(path string, cfg *Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("telemetry: mkdir for %s: %w", path, err)
	}
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("telemetry: create %s: %w", path, err)
	}
	defer f.Close()
	if err := toml.NewEncoder(f).Encode(cfg); err != nil {
		return fmt.Errorf("telemetry: encode %s: %w", path, err)
	}
	return nil
}

// EnsureInstallUUID generates and persists a UUID only when cfg lacks one.
func EnsureInstallUUID(path string, cfg *Config) error {
	if cfg.InstallUUID != "" {
		return nil
	}
	uuid, err := newUUIDv4()
	if err != nil {
		return fmt.Errorf("telemetry: generate install uuid: %w", err)
	}
	cfg.InstallUUID = uuid
	return SaveConfig(path, cfg)
}

func newUUIDv4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// ConfigPath resolves the user's telemetry config path using XDG conventions.
func ConfigPath(home string) string {
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "egress-guard", "telemetry.toml")
	}
	return filepath.Join(home, ".config", "egress-guard", "telemetry.toml")
}
