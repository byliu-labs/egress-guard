package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/byliu-labs/egress-guard/internal/telemetry"
)

func TestTelemetry_EnableThenStatus_PersistsAcrossCalls(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	if err := Telemetry([]string{"enable"}); err != nil {
		t.Fatalf("Telemetry enable: %v", err)
	}

	path := filepath.Join(dir, "egress-guard", "telemetry.toml")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected config file at %s: %v", path, err)
	}
	cfg, err := telemetry.LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if !cfg.Enabled {
		t.Fatal("Enabled = false after telemetry enable")
	}
	if cfg.InstallUUID == "" {
		t.Fatal("InstallUUID empty after telemetry enable")
	}

	if err := Telemetry([]string{"disable"}); err != nil {
		t.Fatalf("Telemetry disable: %v", err)
	}
	cfg, err = telemetry.LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig after disable: %v", err)
	}
	if cfg.Enabled {
		t.Fatal("Enabled = true after telemetry disable")
	}
}

func TestTelemetry_DefaultIsDisabled(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	if err := Telemetry([]string{"status"}); err != nil {
		t.Fatalf("Telemetry status: %v", err)
	}
	path := filepath.Join(dir, "egress-guard", "telemetry.toml")
	if _, err := os.Stat(path); err == nil {
		t.Fatal("status must not create a config file for a never-configured install")
	}
}

func TestTelemetry_UnknownVerbErrors(t *testing.T) {
	if err := Telemetry([]string{"frobnicate"}); err == nil {
		t.Fatal("Telemetry: want error for unknown verb, got nil")
	}
}
