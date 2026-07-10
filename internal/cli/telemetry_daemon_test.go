package cli

import (
	"path/filepath"
	"testing"

	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/telemetry"
)

func TestNewDaemonRatifyWriter_TelemetryDisabledUsesCatalogWriter(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())

	w, err := newDaemonRatifyWriter(filepath.Join(t.TempDir(), "catalog.toml"), &catalog.Catalog{})
	if err != nil {
		t.Fatalf("newDaemonRatifyWriter: %v", err)
	}
	if _, ok := w.(*catalogRatifyWriter); !ok {
		t.Fatalf("writer type = %T, want *catalogRatifyWriter when telemetry is disabled", w)
	}
}

func TestNewDaemonRatifyWriter_TelemetryEnabledWrapsCatalogWriter(t *testing.T) {
	configHome := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configHome)
	t.Setenv("HOME", t.TempDir())

	cfgPath := filepath.Join(configHome, "egress-guard", "telemetry.toml")
	if err := telemetry.SaveConfig(cfgPath, &telemetry.Config{
		Enabled:     true,
		InstallUUID: "uuid-1",
		Endpoint:    "https://example.test/report",
	}); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}

	w, err := newDaemonRatifyWriter(filepath.Join(t.TempDir(), "catalog.toml"), &catalog.Catalog{})
	if err != nil {
		t.Fatalf("newDaemonRatifyWriter: %v", err)
	}
	rw, ok := w.(telemetry.ReportingRatifyWriter)
	if !ok {
		t.Fatalf("writer type = %T, want telemetry.ReportingRatifyWriter when telemetry is enabled", w)
	}
	if _, ok := rw.Inner.(*catalogRatifyWriter); !ok {
		t.Fatalf("inner writer type = %T, want *catalogRatifyWriter", rw.Inner)
	}
	if rw.Cfg.InstallUUID != "uuid-1" {
		t.Fatalf("InstallUUID = %q, want uuid-1", rw.Cfg.InstallUUID)
	}
}
