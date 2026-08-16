package decisionlog

import (
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const segmentTimeFormat = "20060102T150405Z"

const gzSuffix = ".gz"

func segmentName(base string, t time.Time) string {
	return base + "." + t.UTC().Format(segmentTimeFormat)
}

func findSegments(base string) ([]string, error) {
	matches, err := filepath.Glob(base + ".*")
	if err != nil {
		return nil, err
	}
	byStamp := map[string]string{}
	for _, m := range matches {
		stamp := strings.TrimPrefix(m, base+".")
		stamp = strings.TrimSuffix(stamp, gzSuffix)
		if len(stamp) != len(segmentTimeFormat) {
			continue
		}
		if _, err := time.Parse(segmentTimeFormat, stamp); err != nil {
			continue
		}
		if existing, ok := byStamp[stamp]; ok && strings.HasSuffix(existing, gzSuffix) {
			continue
		}
		byStamp[stamp] = m
	}
	out := make([]string, 0, len(byStamp))
	for _, p := range byStamp {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.TrimSuffix(out[i], gzSuffix) < strings.TrimSuffix(out[j], gzSuffix)
	})
	return out, nil
}
