package decisionlog

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const segmentTimeFormat = "20060102T150405Z"

const gzSuffix = ".gz"

const segmentSeqWidth = 6

func segmentName(base string, t time.Time) string {
	return base + "." + t.UTC().Format(segmentTimeFormat)
}

func nextSegmentName(base string, t time.Time) (string, error) {
	stamp := t.UTC().Format(segmentTimeFormat)
	for seq := 0; ; seq++ {
		name := base + "." + stamp
		if seq > 0 {
			name = fmt.Sprintf("%s.%0*d", name, segmentSeqWidth, seq)
		}
		occupied, err := segmentExists(name)
		if err != nil {
			return "", err
		}
		if !occupied {
			return name, nil
		}
	}
}

func segmentExists(path string) (bool, error) {
	for _, candidate := range []string{path, path + gzSuffix, path + gzSuffix + ".tmp"} {
		if _, err := os.Stat(candidate); err == nil {
			return true, nil
		} else if !os.IsNotExist(err) {
			return false, err
		}
	}
	return false, nil
}

func findSegments(base string) ([]string, error) {
	matches, err := filepath.Glob(base + ".*")
	if err != nil {
		return nil, err
	}
	byKey := map[string]string{}
	for _, m := range matches {
		key, ok := segmentKey(base, m)
		if !ok {
			continue
		}
		if existing, ok := byKey[key]; ok && strings.HasSuffix(existing, gzSuffix) {
			continue
		}
		byKey[key] = m
	}
	keys := make([]string, 0, len(byKey))
	for key := range byKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		out = append(out, byKey[key])
	}
	return out, nil
}

func segmentKey(base, path string) (string, bool) {
	suffix := strings.TrimPrefix(path, base+".")
	suffix = strings.TrimSuffix(suffix, gzSuffix)
	stamp := suffix
	if len(suffix) > len(segmentTimeFormat) {
		if suffix[len(segmentTimeFormat)] != '.' {
			return "", false
		}
		seq := suffix[len(segmentTimeFormat)+1:]
		if len(seq) != segmentSeqWidth || !allDigits(seq) {
			return "", false
		}
		stamp = suffix[:len(segmentTimeFormat)]
	}
	if len(stamp) != len(segmentTimeFormat) {
		return "", false
	}
	if _, err := time.Parse(segmentTimeFormat, stamp); err != nil {
		return "", false
	}
	return suffix, true
}

func allDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
