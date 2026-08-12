//go:build darwin

package menubar

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeLog writes the given log lines and pins logPathResolver at that file, so
// the test never picks up the machine's real /var/db system log.
func writeLog(t *testing.T, lines ...string) {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "blocked.log")
	body := ""
	for _, l := range lines {
		body += l + "\n"
	}
	if err := os.WriteFile(logPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	pinLogPath(t, logPath)
}

func pinLogPath(t *testing.T, path string) {
	t.Helper()
	old := logPathResolver
	logPathResolver = func() (string, error) { return path, nil }
	t.Cleanup(func() { logPathResolver = old })
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
	if got[1].Host != "evil-c.com" {
		t.Errorf("last host = %q, want evil-c.com", got[1].Host)
	}
	if !strings.HasSuffix(got[1].Display, "evil-c.com") {
		t.Errorf("last display = %q, want it to end with evil-c.com", got[1].Display)
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
	if got[0].Host != "blocked.example" {
		t.Errorf("RecentBlocks returned wrong entry: %v", got[0])
	}
}

// TestRecentBlocks_ShowsDate guards against the fossil-looks-current bug: a
// months-old entry must render its full date, not just a bare time.
func TestRecentBlocks_ShowsDate(t *testing.T) {
	writeLog(t, `{"ts":"2026-04-30T15:47:36Z","action":"deny","reason":"original_dest_lookup_failed"}`)
	got, err := RecentBlocks(5)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	if !strings.Contains(got[0].Display, "2026-04-30") {
		t.Errorf("display = %q, want it to contain the date 2026-04-30", got[0].Display)
	}
}

// TestRecentBlocks_UnknownHostReason: a host-less deny keeps Host empty (so no
// "Allow" is offered) and explains itself instead of a bare "(unknown host)".
func TestRecentBlocks_UnknownHostReason(t *testing.T) {
	writeLog(t, `{"ts":"2026-04-30T15:47:36Z","action":"deny","reason":"original_dest_lookup_failed"}`)
	got, err := RecentBlocks(5)
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Host != "" {
		t.Errorf("Host = %q, want empty for a host-less deny", got[0].Host)
	}
	if !strings.Contains(got[0].Display, "unknown host") {
		t.Errorf("display = %q, want it to mention unknown host", got[0].Display)
	}
	if !strings.Contains(got[0].Display, "recover the destination") {
		t.Errorf("display = %q, want it to explain the dest-lookup reason", got[0].Display)
	}
}

func TestRecentBlocks_MissingLogIsEmptyNotError(t *testing.T) {
	dir := t.TempDir()
	pinLogPath(t, filepath.Join(dir, "does-not-exist.log"))
	got, err := RecentBlocks(5)
	if err != nil {
		t.Fatalf("expected nil error on missing log, got %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty, got %v", got)
	}
}
