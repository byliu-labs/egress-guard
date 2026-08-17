// Package tail follows append-only files and streams new bytes to an
// io.Writer in real time, using fsnotify for event-driven wake-ups.
//
// Designed for the egress-guard block log, but has no egress-guard-specific
// knowledge — it would work for any append-only line-oriented file.
package tail

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
)

// Follower streams new bytes appended to Path into Out.
// It seeks to end of file at startup, so pre-existing content is not echoed.
type Follower struct {
	Path string
	Out  io.Writer
}

// Follow blocks until ctx is cancelled or an unrecoverable error occurs.
// On clean cancellation (ctx.Err() == context.Canceled) it returns nil.
//
// A Follower holds no internal state, so Follow may be called repeatedly or
// concurrently — each call owns its own watcher and file handle. Callers
// using a single Follower for parallel Follow calls are responsible for
// making Out safe under concurrent writes.
func (f *Follower) Follow(ctx context.Context) error {
	if f.Path == "" {
		return errors.New("tail: Path is empty")
	}
	if f.Out == nil {
		return errors.New("tail: Out is nil")
	}

	var fp *os.File
	defer func() {
		if fp != nil {
			fp.Close()
		}
	}()

	// Snapshot pre-existing content before installing the watcher so a file
	// created after this point is drained from byte 0, not mistaken for old
	// history and skipped by seek-to-end.
	if existing, err := openAndSeekEnd(f.Path); err == nil {
		fp = existing
		if err := drain(fp, f.Out); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	dir := filepath.Dir(f.Path)
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("tail: new watcher: %w", err)
	}
	defer w.Close()

	// Watch the parent directory rather than the file: rename/remove of
	// the file invalidates a file-level watch, but a directory watch sees
	// the create event when a fresh file with the same name appears.
	if err := w.Add(dir); err != nil {
		return fmt.Errorf("tail: watch %s: %w", dir, err)
	}
	if next, err := syncPath(f.Path, fp, f.Out); err != nil {
		return err
	} else {
		fp = next
	}

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			next, err := syncPath(f.Path, fp, f.Out)
			if err != nil {
				return err
			}
			fp = next
		case ev, ok := <-w.Events:
			if !ok {
				return nil
			}
			if ev.Name != f.Path {
				continue
			}
			if ev.Op&(fsnotify.Rename|fsnotify.Remove) != 0 {
				// Old handle is now detached; reopen on the next Create.
				if fp != nil {
					fp.Close()
				}
				fp = nil
			}
			if ev.Op&fsnotify.Create != 0 {
				if fp != nil {
					fp.Close()
				}
				newFp, err := os.Open(f.Path)
				if err != nil {
					return fmt.Errorf("tail: reopen %s: %w", f.Path, err)
				}
				// Don't seek: a freshly-rotated file starts at 0, and we
				// want every byte written to it.
				fp = newFp
				if err := drain(fp, f.Out); err != nil {
					return err
				}
			}
			if ev.Op&fsnotify.Write != 0 {
				if fp == nil {
					// Some filesystems coalesce or drop Create around
					// rotation; a later Write is still enough to reopen.
					newFp, err := os.Open(f.Path)
					if errors.Is(err, os.ErrNotExist) {
						continue
					}
					if err != nil {
						return fmt.Errorf("tail: reopen %s: %w", f.Path, err)
					}
					fp = newFp
				}
				if err := drain(fp, f.Out); err != nil {
					return err
				}
			}
		case err, ok := <-w.Errors:
			if !ok {
				return nil
			}
			return fmt.Errorf("tail: watcher error: %w", err)
		}
	}
}

// drain copies everything from the file's current offset to the writer.
// Returns nil at EOF (the normal case — we'll wake again on the next write).
func drain(fp *os.File, out io.Writer) error {
	buf := make([]byte, 4096)
	for {
		n, err := fp.Read(buf)
		if n > 0 {
			if _, werr := out.Write(buf[:n]); werr != nil {
				return fmt.Errorf("tail: write: %w", werr)
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("tail: read: %w", err)
		}
	}
}

func syncPath(path string, fp *os.File, out io.Writer) (*os.File, error) {
	if fp == nil {
		return openAndDrain(path, out)
	}

	pathInfo, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		fp.Close()
		return nil, nil
	}
	if err != nil {
		return fp, fmt.Errorf("tail: stat %s: %w", path, err)
	}
	openInfo, err := fp.Stat()
	if err != nil {
		return fp, fmt.Errorf("tail: stat open file: %w", err)
	}
	if !os.SameFile(pathInfo, openInfo) {
		fp.Close()
		return openAndDrain(path, out)
	}
	return fp, drain(fp, out)
}

func openAndDrain(path string, out io.Writer) (*os.File, error) {
	fp, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("tail: reopen %s: %w", path, err)
	}
	if err := drain(fp, out); err != nil {
		fp.Close()
		return nil, err
	}
	return fp, nil
}

// openAndSeekEnd opens path read-only and seeks to the end so the follower
// only emits *new* bytes appended after Follow starts.
func openAndSeekEnd(path string) (*os.File, error) {
	fp, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("tail: open %s: %w", path, err)
	}
	if _, err := fp.Seek(0, io.SeekEnd); err != nil {
		fp.Close()
		return nil, fmt.Errorf("tail: seek end: %w", err)
	}
	return fp, nil
}
