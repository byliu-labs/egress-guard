package procid

import (
	"errors"
	"net"
	"sync"
)

// Stub returns canned ProcInfo for tests. Map key is the connection's local
// addr (`conn.LocalAddr().String()`). If empty, the zero ProcInfo is returned.
type Stub struct {
	mu    sync.Mutex
	byKey map[string]ProcInfo
	err   error
}

func NewStub() *Stub { return &Stub{byKey: map[string]ProcInfo{}} }

func (s *Stub) Set(localAddr string, pi ProcInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byKey[localAddr] = pi
}

func (s *Stub) SetErr(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.err = err
}

func (s *Stub) LookupConn(conn net.Conn) (ProcInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return ProcInfo{}, s.err
	}
	if conn == nil || conn.LocalAddr() == nil {
		return ProcInfo{}, errors.New("procid stub: nil conn")
	}
	pi, ok := s.byKey[conn.LocalAddr().String()]
	if !ok {
		return ProcInfo{}, nil
	}
	return pi, nil
}
