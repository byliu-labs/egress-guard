package telemetry

import (
	"encoding/json"
	"testing"

	"github.com/byliu-labs/egress-guard/internal/catalog"
)

func TestNewReport_SetsAllDisclosedFields(t *testing.T) {
	id := catalog.Identity{ExeBasename: "curl", TeamID: "ABCDE12345", SignedRequired: true}
	r := NewReport("uuid-1", id, "api.example.com", "allow")

	if r.InstallUUID != "uuid-1" {
		t.Fatalf("InstallUUID = %q, want %q", r.InstallUUID, "uuid-1")
	}
	if r.Identity != id {
		t.Fatalf("Identity = %+v, want %+v", r.Identity, id)
	}
	if r.Host != "api.example.com" {
		t.Fatalf("Host = %q, want %q", r.Host, "api.example.com")
	}
	if r.Verdict != "allow" {
		t.Fatalf("Verdict = %q, want %q", r.Verdict, "allow")
	}
	if r.SchemaVersion != 1 {
		t.Fatalf("SchemaVersion = %d, want 1", r.SchemaVersion)
	}
}

func TestReport_WireShapeContainsOnlyDisclosedFields(t *testing.T) {
	id := catalog.Identity{ExeBasename: "curl", TeamID: "ABCDE12345"}
	r := NewReport("uuid-1", id, "api.example.com", "allow")

	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	wantKeys := map[string]bool{
		"InstallUUID": true, "Identity": true, "Host": true, "Verdict": true, "SchemaVersion": true,
	}
	if len(raw) != len(wantKeys) {
		t.Fatalf("top-level keys = %v, want exactly %v", keysOf(raw), keysOf(toRaw(wantKeys)))
	}
	for k := range raw {
		if !wantKeys[k] {
			t.Fatalf("unexpected top-level key %q in wire payload", k)
		}
	}

	var identity map[string]json.RawMessage
	if err := json.Unmarshal(raw["Identity"], &identity); err != nil {
		t.Fatalf("Unmarshal Identity: %v", err)
	}
	wantIdentityKeys := map[string]bool{
		"ExeBasename": true, "TeamID": true, "BundleID": true, "SignedRequired": true,
	}
	for k := range identity {
		if !wantIdentityKeys[k] {
			t.Fatalf("unexpected Identity key %q in wire payload", k)
		}
	}
}

func TestLoadConfig_MissingFileDefaultsToDisabled(t *testing.T) {
	cfg, err := LoadConfig(t.TempDir() + "/does-not-exist.toml")
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Enabled {
		t.Fatal("Enabled = true for a missing config file, want false")
	}
}

func TestSaveThenLoadConfig_RoundTrips(t *testing.T) {
	path := t.TempDir() + "/egress-guard/telemetry.toml"
	want := &Config{Enabled: true, InstallUUID: "fixed-uuid", Endpoint: "https://example.test/report"}
	if err := SaveConfig(path, want); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}
	got, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if *got != *want {
		t.Fatalf("LoadConfig = %+v, want %+v", got, want)
	}
}

func TestEnsureInstallUUID_GeneratesAndPersistsOnce(t *testing.T) {
	path := t.TempDir() + "/telemetry.toml"
	cfg := &Config{Enabled: true}
	if err := EnsureInstallUUID(path, cfg); err != nil {
		t.Fatalf("EnsureInstallUUID: %v", err)
	}
	if cfg.InstallUUID == "" {
		t.Fatal("InstallUUID still empty after EnsureInstallUUID")
	}
	first := cfg.InstallUUID

	reloaded, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if err := EnsureInstallUUID(path, reloaded); err != nil {
		t.Fatalf("EnsureInstallUUID (2nd call): %v", err)
	}
	if reloaded.InstallUUID != first {
		t.Fatalf("InstallUUID changed across reload: got %q, want %q", reloaded.InstallUUID, first)
	}
}

func TestConfigPath_RespectsXDGConfigHome(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/xdg/config")
	got := ConfigPath("/home/alice")
	want := "/xdg/config/egress-guard/telemetry.toml"
	if got != want {
		t.Fatalf("ConfigPath = %q, want %q", got, want)
	}
}

func TestConfigPath_FallsBackToDotConfig(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "")
	got := ConfigPath("/home/alice")
	want := "/home/alice/.config/egress-guard/telemetry.toml"
	if got != want {
		t.Fatalf("ConfigPath = %q, want %q", got, want)
	}
}

func keysOf(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func toRaw(m map[string]bool) map[string]json.RawMessage {
	out := make(map[string]json.RawMessage, len(m))
	for k := range m {
		out[k] = nil
	}
	return out
}
