// Package idle reports whether a human was recently at the keyboard.
package idle

import (
	"errors"
	"sync"
	"time"
)

var ErrUnsupported = errors.New("idle: unsupported platform")
var ErrNoSample = errors.New("idle: no usable sample")

const ActiveThreshold = 5 * time.Minute
const neverAgain = 100 * 365 * 24 * time.Hour

// Probe reports seconds since the last human input event.
type Probe interface {
	SecondsSinceInput() (float64, error)
}

// Cached returns the latest sample immediately and refreshes it asynchronously.
// ttl triggers refreshes; maxAge limits how long a sample remains usable.
type Cached struct {
	inner  Probe
	ttl    time.Duration
	maxAge time.Duration

	// OnError receives refresh failures off the decision path.
	OnError func(error)

	mu          sync.Mutex
	sample      *sample
	nextProbeAt time.Time
	inFlight    bool
	failures    int
	now         func() time.Time
}

type sample struct {
	active bool
	at     time.Time
}

func NewCached(p Probe, ttl, maxAge time.Duration) *Cached {
	return &Cached{inner: p, ttl: ttl, maxAge: maxAge, now: wallNow}
}

// wallNow strips the monotonic clock reading time.Now attaches. Go's monotonic
// clock on darwin is mach_absolute_time, which stops while the machine sleeps,
// and Time.Sub/Time.Before use it alone whenever both operands carry one. A
// sample taken before an overnight sleep would therefore look seconds old on a
// 3 a.m. dark wake, defeating maxAge and stamping "the user was here" on
// exactly the connections this bit exists to characterise. Wall time is the
// honest measure of how long ago a human was observed.
func wallNow() time.Time { return time.Now().Round(0) }

// Active never waits for a probe. Before the first sample and after maxAge it
// returns ErrNoSample, which callers must record as absent rather than idle.
func (c *Cached) Active() (bool, error) {
	c.mu.Lock()
	now := c.now()
	if !c.inFlight && !now.Before(c.nextProbeAt) {
		c.inFlight = true
		go c.refresh()
	}
	s := c.sample
	c.mu.Unlock()

	if s == nil || now.Sub(s.at) > c.maxAge {
		return false, ErrNoSample
	}
	return s.active, nil
}

func (c *Cached) refresh() {
	seconds, err := c.inner.SecondsSinceInput()

	c.mu.Lock()
	c.inFlight = false
	if err != nil {
		c.scheduleFailure(err)
		onError := c.OnError
		c.mu.Unlock()
		if onError != nil {
			onError(err)
		}
		return
	}

	at := c.now()
	c.failures = 0
	c.sample = &sample{active: seconds < ActiveThreshold.Seconds(), at: at}
	c.nextProbeAt = at.Add(c.ttl)
	c.mu.Unlock()
}

func (c *Cached) scheduleFailure(err error) {
	c.failures++
	if errors.Is(err, ErrUnsupported) {
		c.nextProbeAt = c.now().Add(neverAgain)
		return
	}
	c.nextProbeAt = c.now().Add(backoff(c.failures, c.ttl))
}

func backoff(failures int, ttl time.Duration) time.Duration {
	delay := ttl
	for i := 1; i < failures && i < 6; i++ {
		delay *= 2
	}
	return delay
}

// Stub is a Probe and reporter for daemon tests.
type Stub struct {
	mu     sync.Mutex
	active bool
	err    error
}

func NewStub() *Stub { return &Stub{active: true} }

func (s *Stub) SetActive(active bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.active, s.err = active, nil
}

func (s *Stub) SetError(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.err = err
}

func (s *Stub) Active() (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active, s.err
}

func (s *Stub) SecondsSinceInput() (float64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return 0, s.err
	}
	if s.active {
		return 0, nil
	}
	return ActiveThreshold.Seconds() + 1, nil
}
