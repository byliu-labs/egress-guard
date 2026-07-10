//go:build darwin

package menubar

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeLog(t *testing.T, lines ...string) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_STATE_HOME", dir)
	egdir := filepath.Join(dir, "egress-guard")
	if err := os.MkdirAll(egdir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := ""
	for _, l := range lines {
		body += l + "\n"
	}
	if err := os.WriteFile(filepath.Join(egdir, "blocked.log"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestRecentBlocks_LastNNewestLast(t *testing.T) {
	writeLog(t,
		`{"ts":"2026-07-09T10:00:00Z","action":"block","host":"evil-a.com"}`,
		`{"ts":"2026-07-09T10:01:00Z","action":"block","host":"evil-b.com"}`,
		`{"ts":"2026-07-09T10:02:00Z","action":"block","host":"evil-c.com"}`,
	)
	got, err := RecentBlocks(2)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2 (%v)", len(got), got)
	}
	if !strings.HasSuffix(got[1], "evil-c.com") {
		t.Errorf("last entry = %q, want it to end with evil-c.com", got[1])
	}
}

func TestRecentBlocks_OnlyDroppedEntries(t *testing.T) {
	writeLog(t,
		`{"ts":"2026-07-09T10:00:00Z","action":"allow","decision":"allow","host":"ok.example"}`,
		`{"ts":"2026-07-09T10:01:00Z","action":"deny","decision":"deny","host":"blocked.example"}`,
	)
	got, err := RecentBlocks(5)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1 (%v)", len(got), got)
	}
	if strings.Contains(got[0], "ok.example") || !strings.Contains(got[0], "blocked.example") {
		t.Errorf("RecentBlocks returned wrong entries: %v", got)
	}
}

func TestRecentBlocks_MissingLogIsEmptyNotError(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_STATE_HOME", dir)
	got, err := RecentBlocks(5)
	if err != nil {
		t.Fatalf("expected nil error on missing log, got %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty, got %v", got)
	}
}
