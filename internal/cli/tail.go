package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/byliu-labs/egress-guard/internal/decisionlog"
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

	f := &tail.Follower{Path: path, Out: newDecisionLogLineRenderer(os.Stdout)}
	return f.Follow(ctx)
}

type decisionLogLineRenderer struct {
	out     io.Writer
	pending []byte
}

func newDecisionLogLineRenderer(out io.Writer) io.Writer {
	return &decisionLogLineRenderer{out: out}
}

func (r *decisionLogLineRenderer) Write(p []byte) (int, error) {
	r.pending = append(r.pending, p...)
	for {
		i := bytes.IndexByte(r.pending, '\n')
		if i < 0 {
			return len(p), nil
		}
		line := strings.TrimSpace(string(r.pending[:i]))
		r.pending = r.pending[i+1:]
		if line == "" {
			continue
		}
		if _, err := fmt.Fprintln(r.out, renderLogLine(line)); err != nil {
			return 0, err
		}
	}
}

func renderLogLine(line string) string {
	var e decisionlog.Entry
	if err := json.Unmarshal([]byte(line), &e); err != nil {
		return line
	}
	return renderEntry(e)
}

func renderEntry(e decisionlog.Entry) string {
	exe := filepath.Base(e.Exe)
	if exe == "." || exe == "" {
		exe = "-"
	}
	host := e.Host
	if host == "" {
		host = "-"
	}
	if e.IsFlow() {
		return fmt.Sprintf("%s  flow   %-24s %-32s up=%s down=%s duration=%s",
			e.Timestamp, exe, host, humanBytes(e.BytesUp), humanBytes(e.BytesDown),
			time.Duration(e.DurationMS)*time.Millisecond)
	}
	action := e.Action
	if action == "" {
		action = string(e.Decision)
	}
	if action == "" {
		action = "-"
	}
	if e.Reason != "" {
		return fmt.Sprintf("%s  %-6s %-24s %-32s %s", e.Timestamp, action, exe, host, e.Reason)
	}
	return fmt.Sprintf("%s  %-6s %-24s %s", e.Timestamp, action, exe, host)
}

// humanBytes renders a byte count compactly for one-line log output.
func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1fG", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1fM", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1fK", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%dB", n)
	}
}
