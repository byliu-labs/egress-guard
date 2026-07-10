package signature

import "sync"

// Stub is a controllable Verifier for tests.
//
// ByExe is exported so tests can use the map-literal init pattern
// (mirrors procid.Stub). The mutex below guards concurrent Verify
// reads against potential late writes; tests that mutate ByExe
// after sharing the Stub with goroutines should use SetByExe.
type Stub struct {
	mu    sync.Mutex
	ByExe map[string]SignedIdentity
	Err   error
}

// NewStub creates a new Stub with an empty canned-identity map.
func NewStub() *Stub {
	return &Stub{ByExe: map[string]SignedIdentity{}}
}

// SetByExe is the concurrency-safe way to add an entry after the
// Stub has been shared with other goroutines.
func (s *Stub) SetByExe(exe string, id SignedIdentity) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ByExe[exe] = id
}

// SetErr is the concurrency-safe way to install a sticky error.
func (s *Stub) SetErr(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Err = err
}

func (s *Stub) Verify(exe string) (SignedIdentity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Err != nil {
		return SignedIdentity{}, s.Err
	}
	if id, ok := s.ByExe[exe]; ok {
		return id, nil
	}
	return SignedIdentity{Valid: false}, nil
}
