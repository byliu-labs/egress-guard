package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/byliu-labs/egress-guard/internal/tail"
)

// Tail follows the block log via fsnotify (kqueue on darwin, inotify on
// linux). On a fresh install where the log doesn't exist yet, Tail blocks
// until the daemon writes its first entry rather than returning early —
// this is the behavior change vs. v0.2.
func Tail(args []string) error {
	fs := flag.NewFlagSet("tail", flag.ExitOnError)
	fs.Parse(args)

	state, err := stateDir()
	if err != nil {
		return fmt.Errorf("resolve state dir: %w", err)
	}
	path := filepath.Join(state, "blocked.log")

	// Make sure the parent directory exists; otherwise fsnotify can't watch
	// it. stateDir() resolution doesn't create the directory itself.
	if err := os.MkdirAll(state, 0o755); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}

	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		// stderr so this notice doesn't pollute the JSONL stream on stdout.
		fmt.Fprintln(os.Stderr, "egress-guard: waiting for first decision (block log not yet created)…")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	f := &tail.Follower{Path: path, Out: os.Stdout}
	return f.Follow(ctx)
}
