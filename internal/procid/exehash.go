package procid

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

// DefaultMaxHashBytes bounds hashing work on the decision path. Anything larger
// is refused rather than stalling a live connection.
const DefaultMaxHashBytes = 256 << 20

type hashKey struct {
	dev   uint64
	ino   uint64
	mtime int64
	ctime int64
	size  int64
}

// ExeHasher resolves an executable path to its realpath and content hash,
// caching by inode identity so the hot path does not re-read the file.
type ExeHasher struct {
	mu       sync.Mutex
	cache    map[hashKey]string
	maxBytes int64
}

func NewExeHasher() *ExeHasher {
	return &ExeHasher{cache: make(map[hashKey]string), maxBytes: DefaultMaxHashBytes}
}

// Hash returns the symlink-resolved path and lowercase-hex SHA-256 of the file.
func (h *ExeHasher) Hash(path string) (string, string, error) {
	if path == "" {
		return "", "", fmt.Errorf("procid: empty executable path")
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", "", fmt.Errorf("procid: resolve %s: %w", path, err)
	}
	fi, err := os.Stat(real)
	if err != nil {
		return "", "", fmt.Errorf("procid: stat %s: %w", real, err)
	}
	maxBytes := h.maxBytes
	if maxBytes == 0 {
		maxBytes = DefaultMaxHashBytes
	}
	if fi.Size() > maxBytes {
		return "", "", fmt.Errorf("procid: %s is %d bytes, over the %d hashing limit", real, fi.Size(), maxBytes)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return "", "", fmt.Errorf("procid: cannot determine inode identity for %s", real)
	}
	key := hashKey{dev: uint64(st.Dev), ino: uint64(st.Ino), mtime: fi.ModTime().UnixNano(), ctime: ctimeNanos(st), size: fi.Size()}

	h.mu.Lock()
	if h.cache == nil {
		h.cache = make(map[hashKey]string)
	}
	sum, hit := h.cache[key]
	h.mu.Unlock()
	if hit {
		return real, sum, nil
	}

	f, err := os.Open(real)
	if err != nil {
		return "", "", fmt.Errorf("procid: open %s: %w", real, err)
	}
	defer f.Close()
	d := sha256.New()
	if _, err := io.Copy(d, io.LimitReader(f, maxBytes)); err != nil {
		return "", "", fmt.Errorf("procid: read %s: %w", real, err)
	}
	sum = hex.EncodeToString(d.Sum(nil))

	h.mu.Lock()
	h.cache[key] = sum
	h.mu.Unlock()
	return real, sum, nil
}
