package decisionlog

import (
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

func ReadHistory(path string) ([]Entry, error) {
	segments, err := findSegments(path)
	if err != nil {
		return nil, fmt.Errorf("decisionlog: find segments for %s: %w", path, err)
	}
	var all []Entry
	for _, seg := range segments {
		entries, err := readSegment(seg)
		if err != nil {
			continue
		}
		all = append(all, entries...)
	}
	live, err := Read(path)
	if err != nil {
		if len(segments) > 0 && errors.Is(err, os.ErrNotExist) {
			return all, nil
		}
		return nil, err
	}
	return append(all, live...), nil
}

func readSegment(path string) ([]Entry, error) {
	if !strings.HasSuffix(path, gzSuffix) {
		return Read(path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("decisionlog: open segment %s: %w", path, err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("decisionlog: gzip reader %s: %w", path, err)
	}
	defer zr.Close()
	raw, err := io.ReadAll(zr)
	if err != nil {
		return nil, fmt.Errorf("decisionlog: decompress %s: %w", path, err)
	}
	return parseEntries(string(raw), path)
}
