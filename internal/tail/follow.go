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

	var fp *os.File
	defer func() {
		if fp != nil {
			fp.Close()
		}
	}()

	// Open if it already exists. If it doesn't, we'll catch the Create
	// event below — same code path the rotation case already exercises.
	if existing, err := openAndSeekEnd(f.Path); err == nil {
		fp = existing
		if err := drain(fp, f.Out); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case ev, ok := <-w.Events:
			if !ok {
				return nil
			}
			if ev.Name != f.Path {
				continue
			}
			switch {
			case ev.Op&fsnotify.Write != 0:
				if fp == nil {
					// A Write event can arrive before Create on some
					// filesystems; skip until the Create branch opens fp.
					continue
				}
				if err := drain(fp, f.Out); err != nil {
					return err
				}
			case ev.Op&(fsnotify.Rename|fsnotify.Remove) != 0:
				// Old handle is now detached; reopen on the next Create.
				if fp != nil {
					fp.Close()
				}
				fp = nil
			case ev.Op&fsnotify.Create != 0:
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
