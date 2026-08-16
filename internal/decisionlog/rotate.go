package decisionlog

import (
	"fmt"
	"os"
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
	return w, nil
}

func (w *Writer) rotateLocked() error {
	if err := w.f.Close(); err != nil {
		return fmt.Errorf("decisionlog: close before rotate: %w", err)
	}
	seg := segmentName(w.path, w.opts.Now())
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
	return nil
}
