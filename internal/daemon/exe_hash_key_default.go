//go:build !darwin && !linux

package daemon

import "os"

func executableCacheKey(path string, info os.FileInfo) string {
	return baseExecutableCacheKey(path, info)
}
