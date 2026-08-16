package tail

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// safeBuffer is bytes.Buffer with a mutex — Follower writes from a goroutine
// while the test reads from the test goroutine. A bare bytes.Buffer would
// race under -race.
type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *safeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *safeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// waitFor polls fn until it returns true or the deadline elapses. Used to
// bridge "fsnotify event was queued by the kernel" vs "Follower goroutine
// has actually drained the file." 5s is generous; on a healthy machine the
// event arrives in <50ms.
func waitFor(t *testing.T, fn func() bool) {
	t.Helper()
	if waitUntil(fn) {
		return
	}
	t.Fatalf("waitFor: condition not met within 5s")
}

func TestFollower_AppendsAfterStart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blocked.log")

	// Pre-existing content that the follower should NOT echo (it seeks to end).
	if err := os.WriteFile(path, []byte("OLD\n"), 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	out := &safeBuffer{}
	f := &Follower{Path: path, Out: out}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- f.Follow(ctx) }()

	// Give the follower a chance to attach before we write. Without this we
	// race the watcher setup; the test would still pass via the polling
	// inside waitFor, but slowing down once at startup is cheaper than
	// debugging spurious failures.
	time.Sleep(100 * time.Millisecond)

	fp, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("open for append: %v", err)
	}
	if _, err := fp.WriteString("NEW\n"); err != nil {
		t.Fatalf("append: %v", err)
	}
	fp.Close()

	waitFor(t, func() bool { return out.String() == "NEW\n" })

	cancel()
	if err := <-errCh; err != nil && err != context.Canceled {
		t.Fatalf("Follow returned %v, want nil or context.Canceled", err)
	}
}

func TestFollower_HandlesRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blocked.log")
	if err := os.WriteFile(path, []byte(""), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	out := &safeBuffer{}
	f := &Follower{Path: path, Out: out}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- f.Follow(ctx) }()
	time.Sleep(100 * time.Millisecond)

	// Write to the original file.
	if err := appendLine(path, "BEFORE\n"); err != nil {
		t.Fatalf("append before: %v", err)
	}
	waitFor(t, func() bool { return out.String() == "BEFORE\n" })

	// Rotate: mv blocked.log blocked.log.1 ; create fresh blocked.log
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if err := os.WriteFile(path, []byte(""), 0o644); err != nil {
		t.Fatalf("recreate: %v", err)
	}

	// Give the follower a beat to notice the rotation and re-attach.
	// 300ms covers the race-detector overhead (which can be 2-3x slower).
	time.Sleep(300 * time.Millisecond)

	// New write to the new file should appear.
	if err := appendLine(path, "AFTER\n"); err != nil {
		t.Fatalf("append after: %v", err)
	}
	waitFor(t, func() bool { return out.String() == "BEFORE\nAFTER\n" })

	cancel()
	if err := <-errCh; err != nil && err != context.Canceled {
		t.Fatalf("Follow returned %v after rotation, want nil or context.Canceled", err)
	}
}

func TestFollower_WaitsForLateCreate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blocked.log")
	// NOTE: file does not exist yet.

	out := &safeBuffer{}
	f := &Follower{Path: path, Out: out}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	appendDone := make(chan error, 1)
	go func() {
		time.Sleep(100 * time.Millisecond)
		// Now create the file and write to it; the follower should pick it up.
		if err := appendLine(path, "FIRST\n"); err != nil {
			appendDone <- err
			cancel()
			return
		}
		if !waitUntil(func() bool { return out.String() == "FIRST\n" }) {
			appendDone <- errors.New("late-created file was not drained within 5s; got " + out.String())
			cancel()
			return
		}
		appendDone <- nil
		cancel()
	}()

	if err := f.Follow(ctx); err != nil && err != context.Canceled {
		t.Fatalf("Follow returned %v after late create, want nil or context.Canceled", err)
	}
	if err := <-appendDone; err != nil {
		t.Fatalf("create+append: %v", err)
	}
}

func waitUntil(fn func() bool) bool {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if fn() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

func TestFollower_HandlesAtomicReplace(t *testing.T) {
	watchedDir := t.TempDir()
	sourceDir := t.TempDir() // separate dir, not watched
	path := filepath.Join(watchedDir, "blocked.log")
	if err := os.WriteFile(path, []byte(""), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	out := &safeBuffer{}
	f := &Follower{Path: path, Out: out}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- f.Follow(ctx) }()
	time.Sleep(100 * time.Millisecond)

	if err := appendLine(path, "BEFORE\n"); err != nil {
		t.Fatalf("append before: %v", err)
	}
	waitFor(t, func() bool { return out.String() == "BEFORE\n" })

	// Atomic in-place replace: build a fresh file in a different dir and
	// rename it onto the watched path. This mirrors what tools like
	// `install` or shell `mv /tmp/new.log ./blocked.log` produce — a
	// single rename(2) syscall that the parent-dir watcher sees as a
	// Create (or Rename) event for the destination, with no Remove of
	// the prior inode.
	replacement := filepath.Join(sourceDir, "new.log")
	if err := os.WriteFile(replacement, []byte("REPLACED\n"), 0o644); err != nil {
		t.Fatalf("write replacement: %v", err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatalf("atomic replace: %v", err)
	}

	waitFor(t, func() bool { return out.String() == "BEFORE\nREPLACED\n" })

	cancel()
	if err := <-errCh; err != nil && err != context.Canceled {
		t.Fatalf("Follow returned %v after atomic replace, want nil or context.Canceled", err)
	}
}

func appendLine(path, s string) error {
	fp, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		return err
	}
	defer fp.Close()
	_, err = fp.WriteString(s)
	return err
}
