package decisionlog

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

const DefaultMaxBytes int64 = 64 << 20

type Options struct {
	MaxBytes    int64
	MaxSegments int
	Now         func() time.Time
}

func (o Options) withDefaults() Options {
	if o.MaxBytes == 0 {
		o.MaxBytes = DefaultMaxBytes
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return o
}

func OpenWithOptions(path string, opts Options) (*Writer, error) {
	w, err := openWriter(path)
	if err != nil {
		return nil, err
	}
	w.opts = opts.withDefaults()
	fi, err := w.f.Stat()
	if err != nil {
		w.f.Close()
		return nil, fmt.Errorf("decisionlog: stat %s: %w", path, err)
	}
	w.size = fi.Size()
	_ = sweepUncompressed(path)
	return w, nil
}

func (w *Writer) rotateLocked() error {
	seg, err := nextSegmentName(w.path, w.opts.Now())
	if err != nil {
		return fmt.Errorf("decisionlog: choose segment name: %w", err)
	}
	if err := w.f.Close(); err != nil {
		return fmt.Errorf("decisionlog: close before rotate: %w", err)
	}
	if err := os.Rename(w.path, seg); err != nil {
		if f, oerr := os.OpenFile(w.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); oerr == nil {
			w.f = f
		}
		return fmt.Errorf("decisionlog: rotate rename: %w", err)
	}
	f, err := os.OpenFile(w.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("decisionlog: reopen after rotate: %w", err)
	}
	w.f = f
	w.size = 0
	w.wg.Add(1)
	go func(seg string) {
		defer w.wg.Done()
		if err := compressSegment(seg); err != nil {
			return
		}
		_ = pruneSegments(w.path, w.opts.MaxSegments)
	}(seg)
	return nil
}

func compressSegment(path string) error {
	in, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("decisionlog: compress open %s: %w", path, err)
	}
	defer in.Close()

	tmp := path + gzSuffix + ".tmp"
	out, err := os.Create(tmp)
	if err != nil {
		return fmt.Errorf("decisionlog: compress create %s: %w", tmp, err)
	}
	zw := gzip.NewWriter(out)
	if _, err := io.Copy(zw, in); err != nil {
		zw.Close()
		out.Close()
		os.Remove(tmp)
		return fmt.Errorf("decisionlog: compress copy %s: %w", path, err)
	}
	if err := zw.Close(); err != nil {
		out.Close()
		os.Remove(tmp)
		return fmt.Errorf("decisionlog: compress finish %s: %w", path, err)
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("decisionlog: compress close %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path+gzSuffix); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("decisionlog: compress rename %s: %w", tmp, err)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("decisionlog: compress remove plain %s: %w", path, err)
	}
	return nil
}

func sweepUncompressed(base string) error {
	segs, err := findSegments(base)
	if err != nil {
		return err
	}
	for _, s := range segs {
		if strings.HasSuffix(s, gzSuffix) {
			continue
		}
		if err := compressSegment(s); err != nil {
			return err
		}
	}
	return nil
}

func pruneSegments(base string, max int) error {
	if max <= 0 {
		return nil
	}
	segs, err := findSegments(base)
	if err != nil {
		return err
	}
	if len(segs) <= max {
		return nil
	}
	for _, s := range segs[:len(segs)-max] {
		if err := os.Remove(s); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("decisionlog: prune %s: %w", s, err)
		}
	}
	return nil
}
