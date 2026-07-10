package decisionlog

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/byliu-labs/egress-guard/internal/persist"
)

func TestWriter_WritesJSONLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "decisions.log")
	w, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer w.Close()

	err = w.Write(Entry{
		Decision: DecisionDeny,
		Action:   "deny",
		Reason:   "unknown_host",
		Host:     "evil.example.com",
		DestIP:   "203.0.113.42",
		DestPort: 443,
	})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	line := strings.TrimRight(string(b), "\n")
	var got Entry
	if err := json.Unmarshal([]byte(line), &got); err != nil {
		t.Fatalf("Unmarshal: %v\nline: %q", err, line)
	}
	if got.Host != "evil.example.com" || got.Action != "deny" {
		t.Errorf("entry = %+v, want host=evil.example.com action=deny", got)
	}
	if got.Timestamp == "" {
		t.Error("timestamp should be auto-set")
	}
}

func TestWriter_AppendsMultiple(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "decisions.log")
	w, _ := Open(path)
	defer w.Close()

	for _, h := range []string{"a.com", "b.com", "c.com"} {
		_ = w.Write(Entry{Decision: DecisionDeny, Action: "deny", Host: h})
	}

	b, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) != 3 {
		t.Errorf("expected 3 lines, got %d", len(lines))
	}
}

func TestWriter_CreatesParentDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "deep", "decisions.log")
	w, err := Open(path)
	if err != nil {
		t.Fatalf("Open with missing parent dir: %v", err)
	}
	defer w.Close()
	if _, err := os.Stat(filepath.Dir(path)); err != nil {
		t.Errorf("parent dir not created: %v", err)
	}
}

func TestEntry_ProcContextSerialized(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(filepath.Join(dir, "log.jsonl"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer w.Close()

	if err := w.Write(Entry{
		Decision: DecisionAllow,
		Action:   "allow",
		Host:     "api.openai.com",
		PID:      12345,
		Exe:      "/usr/bin/curl",
		Comm:     "curl",
		Argv:     []string{"curl", "-sS", "https://api.openai.com/v1/chat/completions"},
		Cwd:      "/Users/alice",
		PPID:     12340,
		PName:    "zsh",
	}); err != nil {
		t.Fatalf("write: %v", err)
	}

	b, _ := os.ReadFile(filepath.Join(dir, "log.jsonl"))
	for _, want := range []string{
		`"pid":12345`, `"ppid":12340`, `"pname":"zsh"`, `"cwd":"/Users/alice"`,
		`"argv":["curl"`, `"comm":"curl"`,
	} {
		if !strings.Contains(string(b), want) {
			t.Errorf("missing %q in %s", want, b)
		}
	}
}

func TestEntry_DecisionMetadataSerialized(t *testing.T) {
	dir := t.TempDir()
	w, _ := Open(filepath.Join(dir, "log.jsonl"))
	defer w.Close()

	if err := w.Write(Entry{
		Decision:  DecisionObserve,
		Action:    "deny",
		Reason:    "host_denylisted",
		TrustTier: TierPrompt,
		Host:      "shadowed.example",
		TeamID:    "TESTTEAM",
		SigValid:  true,
	}); err != nil {
		t.Fatalf("write: %v", err)
	}

	b, _ := os.ReadFile(filepath.Join(dir, "log.jsonl"))
	for _, want := range []string{
		`"decision":"observe"`, `"action":"deny"`, `"trust_tier":"prompt"`,
		`"team_id":"TESTTEAM"`, `"sig_valid":true`,
	} {
		if !strings.Contains(string(b), want) {
			t.Errorf("missing %q in %s", want, b)
		}
	}
}

func TestWriter_BackCompatActionOnlyFieldsStillParse(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blocked.log")
	w, _ := Open(path)
	defer w.Close()

	_ = w.Write(Entry{Action: "deny", Reason: "unknown_host", Host: "evil.example.com"})

	b, _ := os.ReadFile(path)
	var raw map[string]any
	if err := json.Unmarshal(b[:len(b)-1], &raw); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if raw["action"] != "deny" || raw["host"] != "evil.example.com" {
		t.Errorf("raw = %+v, want action=deny host=evil.example.com", raw)
	}
}

func TestEntry_PersistenceFieldRoundTrips(t *testing.T) {
	firstSeen := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	e := Entry{
		Decision: DecisionAllow,
		Action:   "allow",
		Host:     "example.com",
		Persistence: &persist.Source{
			Kind:      persist.KindLaunchd,
			Label:     "com.example.beacon",
			FirstSeen: firstSeen,
			New:       true,
		},
	}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got Entry
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Persistence == nil {
		t.Fatal("Persistence is nil after round-trip")
	}
	if got.Persistence.Kind != persist.KindLaunchd || got.Persistence.Label != "com.example.beacon" {
		t.Errorf("Persistence = %+v, want Kind=launchd Label=com.example.beacon", got.Persistence)
	}
	if !got.Persistence.New {
		t.Error("Persistence.New = false, want true")
	}
}

func TestEntry_PersistenceOmittedWhenNil(t *testing.T) {
	e := Entry{Decision: DecisionAllow, Action: "allow", Host: "example.com"}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), `"persistence"`) {
		t.Errorf("expected no \"persistence\" key when nil, got: %s", b)
	}
}
