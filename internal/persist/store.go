package persist

import (
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"sync"
	"time"
)

var storeMu sync.Mutex

func stateFilePath() (string, error) {
	if x := os.Getenv("XDG_STATE_HOME"); x != "" {
		return filepath.Join(x, "egress-guard", "persistence-seen.json"), nil
	}
	home, err := resolveHome()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "state", "egress-guard", "persistence-seen.json"), nil
}

func resolveHome() (string, error) {
	if h, err := os.UserHomeDir(); err == nil && h != "" {
		return h, nil
	}
	if u, err := user.Current(); err == nil && u.HomeDir != "" {
		return u.HomeDir, nil
	}
	return "", fmt.Errorf("persist: cannot resolve home directory: $HOME unset and os/user lookup failed")
}

func recordFirstSeen(kind SourceKind, label string) (time.Time, bool, error) {
	path, err := stateFilePath()
	if err != nil {
		return time.Time{}, false, err
	}
	key := string(kind) + "|" + label

	storeMu.Lock()
	defer storeMu.Unlock()

	seen, err := loadSeen(path)
	if err != nil {
		return time.Time{}, false, err
	}
	if t, ok := seen[key]; ok {
		return t, false, nil
	}
	now := time.Now().UTC()
	seen[key] = now
	if err := saveSeen(path, seen); err != nil {
		return time.Time{}, false, err
	}
	return now, true, nil
}

func loadSeen(path string) (map[string]time.Time, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return map[string]time.Time{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("persist: read seen ledger: %w", err)
	}
	var seen map[string]time.Time
	if err := json.Unmarshal(b, &seen); err != nil {
		return nil, fmt.Errorf("persist: parse seen ledger: %w", err)
	}
	if seen == nil {
		seen = map[string]time.Time{}
	}
	return seen, nil
}

func saveSeen(path string, seen map[string]time.Time) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("persist: mkdir: %w", err)
	}
	b, err := json.Marshal(seen)
	if err != nil {
		return fmt.Errorf("persist: marshal seen ledger: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return fmt.Errorf("persist: write temp seen ledger: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("persist: rename seen ledger: %w", err)
	}
	return nil
}
