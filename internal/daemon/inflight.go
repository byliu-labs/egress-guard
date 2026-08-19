package daemon

import "sync"

// inflight tracks connections the daemon currently has open, so a connection
// being adjudicated right now can be told how much else is egressing.
//
// This is NOT a collector and is never persisted. Historical concurrency is
// derived from the log by decisionlog.ConcurrencyIndex; this only covers the
// connections that have not closed yet and are therefore not in the log.
type inflight struct {
	mu    sync.Mutex
	conns map[string]struct{}
}

func newInflight() *inflight {
	return &inflight{conns: make(map[string]struct{})}
}

func (f *inflight) open(connID string) {
	if connID == "" {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.conns[connID] = struct{}{}
}

func (f *inflight) done(connID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.conns, connID)
}

// count returns how many connections other than exclude are open.
func (f *inflight) count(exclude string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := len(f.conns)
	if _, ok := f.conns[exclude]; ok {
		n--
	}
	return n
}
