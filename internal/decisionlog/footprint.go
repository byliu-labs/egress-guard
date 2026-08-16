package decisionlog

import "os"

// Footprint reports the live decision log plus valid rotated segments.
func Footprint(path string) (int, int64, error) {
	var total int64
	if fi, err := os.Stat(path); err == nil {
		total += fi.Size()
	} else if !os.IsNotExist(err) {
		return 0, 0, err
	}

	segs, err := findSegments(path)
	if err != nil {
		return 0, 0, err
	}
	for _, seg := range segs {
		fi, err := os.Stat(seg)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return 0, 0, err
		}
		total += fi.Size()
	}
	return len(segs), total, nil
}
