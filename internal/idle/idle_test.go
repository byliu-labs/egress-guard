package idle

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type countingProbe struct {
	mu    sync.Mutex
	calls int
	secs  float64
	err   error
}

func (p *countingProbe) SecondsSinceInput() (float64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	return p.secs, p.err
}

func (p *countingProbe) count() int       { p.mu.Lock(); defer p.mu.Unlock(); return p.calls }
func (p *countingProbe) setErr(err error) { p.mu.Lock(); defer p.mu.Unlock(); p.err = err }

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) advance(d time.Duration) { c.mu.Lock(); defer c.mu.Unlock(); c.t = c.t.Add(d) }

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition never held within 2s")
}

type blockingProbe struct{ release chan struct{} }

func (p *blockingProbe) SecondsSinceInput() (float64, error) { <-p.release; return 1, nil }

func TestCached_ActiveNeverBlocksOnTheProbe(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	c := NewCached(&blockingProbe{release: release}, time.Minute, time.Hour)
	done := make(chan struct{})
	go func() { c.Active(); c.Active(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Active blocked on the probe")
	}
}

func TestCached_FirstCallReportsNoSample(t *testing.T) {
	c := NewCached(&countingProbe{secs: 5}, time.Minute, time.Hour)
	active, err := c.Active()
	if !errors.Is(err, ErrNoSample) || active {
		t.Fatalf("Active() = %v, %v; want false, ErrNoSample", active, err)
	}
}

func TestCached_ServesSample(t *testing.T) {
	inner := &countingProbe{secs: ActiveThreshold.Seconds() - 1}
	c := NewCached(inner, time.Minute, time.Hour)
	c.Active()
	waitFor(t, func() bool { return inner.count() == 1 })
	active, err := c.Active()
	if err != nil || !active {
		t.Fatalf("Active() = %v, %v; want true, nil", active, err)
	}
}

func TestCached_IdleAboveThreshold(t *testing.T) {
	inner := &countingProbe{secs: ActiveThreshold.Seconds() + 1}
	c := NewCached(inner, time.Minute, time.Hour)
	c.Active()
	waitFor(t, func() bool { return inner.count() == 1 })
	active, err := c.Active()
	if err != nil || active {
		t.Fatalf("Active() = %v, %v; want false, nil", active, err)
	}
}

func TestCached_BurstCostsOneProbe(t *testing.T) {
	inner := &countingProbe{secs: 5}
	c := NewCached(inner, time.Minute, time.Hour)
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() { defer wg.Done(); c.Active() }()
	}
	wg.Wait()
	waitFor(t, func() bool { return inner.count() >= 1 })
	if got := inner.count(); got != 1 {
		t.Errorf("probed %d times, want 1", got)
	}
}

func TestCached_SampleOlderThanMaxAgeReadsAsUnknown(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1700000000, 0)}
	inner := &countingProbe{secs: 1}
	c := NewCached(inner, time.Minute, 5*time.Minute)
	c.now = clock.Now
	c.Active()
	waitFor(t, func() bool { return inner.count() == 1 })
	if _, err := c.Active(); err != nil {
		t.Fatalf("fresh sample: %v", err)
	}
	inner.setErr(errors.New("ioreg gone"))
	clock.advance(6 * time.Minute)
	active, err := c.Active()
	if !errors.Is(err, ErrNoSample) || active {
		t.Fatalf("Active() = %v, %v; want false, ErrNoSample", active, err)
	}
}

func TestCached_UnsupportedPlatformProbesOnceAndStops(t *testing.T) {
	inner := &countingProbe{err: ErrUnsupported}
	c := NewCached(inner, time.Millisecond, time.Hour)
	for range 20 {
		c.Active()
		time.Sleep(time.Millisecond)
	}
	waitFor(t, func() bool { return inner.count() >= 1 })
	if got := inner.count(); got != 1 {
		t.Errorf("probed %d times, want 1", got)
	}
}

func TestCached_ErrorsReportedOncePerBackoffNotPerCall(t *testing.T) {
	var reported int32
	c := NewCached(&countingProbe{err: errors.New("transient")}, time.Hour, time.Hour)
	c.OnError = func(error) { atomic.AddInt32(&reported, 1) }
	for range 100 {
		c.Active()
	}
	waitFor(t, func() bool { return atomic.LoadInt32(&reported) >= 1 })
	if got := atomic.LoadInt32(&reported); got != 1 {
		t.Errorf("reported %d errors, want 1", got)
	}
}

func TestCached_FailureKeepsThePreviousSample(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1700000000, 0)}
	inner := &countingProbe{secs: 1}
	c := NewCached(inner, time.Minute, time.Hour)
	c.now = clock.Now
	c.Active()
	waitFor(t, func() bool { return inner.count() == 1 })
	inner.setErr(errors.New("transient"))
	clock.advance(2 * time.Minute)
	c.Active()
	waitFor(t, func() bool { return inner.count() == 2 })
	active, err := c.Active()
	if err != nil || !active {
		t.Fatalf("Active() = %v, %v; want true, nil", active, err)
	}
}

func TestStub_ReturnsConfiguredValue(t *testing.T) {
	s := NewStub()
	s.SetActive(false)
	active, err := s.Active()
	if err != nil || active {
		t.Errorf("Active() = %v, %v; want false, nil", active, err)
	}
}

// A sample must be dated by wall time, not by Go's monotonic clock. On darwin
// the monotonic clock is mach_absolute_time, which stops while the machine is
// asleep, so a monotonic-dated sample survives an overnight sleep looking
// seconds old — maxAge never fires and the pre-sleep verdict is served to the
// 3 a.m. connections this bit exists to characterise. The fake clocks used
// elsewhere in this file return time.Unix values, which carry no monotonic
// reading, so no other test can catch this.
func TestCached_SampleIsDatedByWallClockSoItSurvivesSleep(t *testing.T) {
	inner := &countingProbe{secs: 1}
	c := NewCached(inner, time.Minute, time.Hour)
	c.Active()
	waitFor(t, func() bool { return inner.count() == 1 })

	c.mu.Lock()
	at, next := c.sample.at, c.nextProbeAt
	c.mu.Unlock()

	if at != at.Round(0) {
		t.Errorf("sample.at carries a monotonic reading (%v); it will not survive system sleep", at)
	}
	if next != next.Round(0) {
		t.Errorf("nextProbeAt carries a monotonic reading (%v); refreshes will not resume after sleep", next)
	}
}
