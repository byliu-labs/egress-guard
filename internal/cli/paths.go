package cli

import (
	"fmt"
	"os"
	"path/filepath"
)

func RejectedPairsPath() (string, error) {
	if path := os.Getenv("EGRESS_GUARD_REJECTION_PATH"); path != "" {
		if !filepath.IsAbs(path) {
			return "", fmt.Errorf("rejection path must be absolute: %q", path)
		}
		return path, nil
	}
	return configPath("rejected-pairs.jsonl")
}

// BlockLogPath returns the absolute path to the daemon's decision log. It is
// the exported entry point for out-of-package consumers so stateDir()
// resolution rules live in exactly one place.
func BlockLogPath() (string, error) {
	dir, err := stateDir()
	if err != nil {
		return "", fmt.Errorf("resolve state dir: %w", err)
	}
	return filepath.Join(dir, "blocked.log"), nil
}
