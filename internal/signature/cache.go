package signature

import (
	"container/list"
	"os"
	"sync"
)

// CachingVerifier wraps an inner Verifier with a per-exe LRU cache keyed by
// (exe path, mtime). Avoids repeated codesign forks for the same binary —
// e.g., a script running 100 short HTTPS requests would otherwise fork
// codesign 100 times.
//
// Invalidation: a binary update changes mtime, so the next Verify falls
// through to the inner verifier and reseeds the cache.
type CachingVerifier struct {
	inner Verifier
	max   int

	mu    sync.Mutex
	lru   *list.List
	index map[string]*list.Element
}

type cacheEntry struct {
	key string // exe + "\x00" + mtime nanos
	id  SignedIdentity
	err error
}

// NewCachingVerifier wraps inner with an LRU cache of up to max entries.
// max=256 ≈ 16KB heap and is plenty for any laptop's process count.
func NewCachingVerifier(inner Verifier, max int) *CachingVerifier {
	return &CachingVerifier{
		inner: inner,
		max:   max,
		lru:   list.New(),
		index: map[string]*list.Element{},
	}
}

func (c *CachingVerifier) Verify(exe string) (SignedIdentity, error) {
	info, statErr := os.Stat(exe)
	if statErr != nil {
		// Bypass cache when we can't compute the (exe, mtime) key.
		// Inner verifier will surface the real "not found" / perm error.
		return c.inner.Verify(exe)
	}
	key := exe + "\x00" + info.ModTime().UTC().Format("2006-01-02T15:04:05.000000000Z")

	c.mu.Lock()
	if elem, ok := c.index[key]; ok {
		c.lru.MoveToFront(elem)
		ent := elem.Value.(*cacheEntry)
		c.mu.Unlock()
		return ent.id, ent.err
	}
	c.mu.Unlock()

	id, err := c.inner.Verify(exe)

	c.mu.Lock()
	defer c.mu.Unlock()
	if elem, ok := c.index[key]; ok {
		// Race: another goroutine populated. Prefer existing entry.
		c.lru.MoveToFront(elem)
		ent := elem.Value.(*cacheEntry)
		return ent.id, ent.err
	}
	ent := &cacheEntry{key: key, id: id, err: err}
	elem := c.lru.PushFront(ent)
	c.index[key] = elem
	if c.lru.Len() > c.max {
		oldest := c.lru.Back()
		c.lru.Remove(oldest)
		delete(c.index, oldest.Value.(*cacheEntry).key)
	}
	return id, err
}
