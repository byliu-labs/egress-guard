package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/byliu-labs/egress-guard/internal/catalog"
)

// catalogRatifyWriter persists a user ratification to disk and to the live
// catalog the daemon consults. catalog.Catalog must make Add safe with Lookup
// when ratification and other connection decisions run concurrently.
type catalogRatifyWriter struct {
	path string
	cat  *catalog.Catalog
	mu   sync.Mutex
}

func newCatalogRatifyWriter(path string, cat *catalog.Catalog) *catalogRatifyWriter {
	return &catalogRatifyWriter{path: path, cat: cat}
}

func (w *catalogRatifyWriter) Ratify(e catalog.Entry) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(w.path), 0o755); err != nil {
		return fmt.Errorf("ratifywriter: mkdir: %w", err)
	}

	onDisk, err := catalog.LoadLayerFile("user", w.path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("ratifywriter: read %s: %w", w.path, err)
		}
		onDisk = &catalog.Catalog{}
	}
	added, err := onDisk.AddIfAbsent(e)
	if err != nil {
		return fmt.Errorf("ratifywriter: validate entry: %w", err)
	}
	if added {
		b, err := onDisk.Marshal()
		if err != nil {
			return fmt.Errorf("ratifywriter: marshal: %w", err)
		}
		if err := writeCatalogAtomic(w.path, b); err != nil {
			return err
		}
	}
	if w.cat != nil {
		if _, err := w.cat.AddIfAbsent(e); err != nil {
			return fmt.Errorf("ratifywriter: update live catalog: %w", err)
		}
	}
	return nil
}

func writeCatalogAtomic(path string, b []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return fmt.Errorf("ratifywriter: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("ratifywriter: rename: %w", err)
	}
	return nil
}
