//go:build darwin

package daemon

import (
	"os"
	"strconv"
	"syscall"
)

func executableCacheKey(path string, info os.FileInfo) string {
	key := baseExecutableCacheKey(path, info)
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		key += "\x00dev=" + strconv.FormatInt(int64(st.Dev), 10)
		key += "\x00ino=" + strconv.FormatUint(st.Ino, 10)
		key += "\x00ctime=" + strconv.FormatInt(st.Ctimespec.Sec, 10) + "." + strconv.FormatInt(st.Ctimespec.Nsec, 10)
	}
	return key
}
