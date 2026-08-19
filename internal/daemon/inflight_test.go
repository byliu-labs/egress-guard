package daemon

import (
	"strconv"
	"sync"
	"testing"
)

func TestInflight_CountsOpenConnections(t *testing.T) {
	f := newInflight()
	f.open("a")
	f.open("b")
	f.open("c")
	if got := f.count(""); got != 3 {
		t.Errorf("count = %d, want 3", got)
	}
	f.done("b")
	if got := f.count(""); got != 2 {
		t.Errorf("count after done = %d, want 2", got)
	}
}

func TestInflight_ExcludesTheSubject(t *testing.T) {
	f := newInflight()
	f.open("a")
	if got := f.count("a"); got != 0 {
		t.Errorf("count excluding self = %d, want 0", got)
	}
}

// Closing a connection that was never opened must not drive the count
// negative — a negative concurrency would corrupt log1p downstream.
func TestInflight_DoneOfUnknownIsSafe(t *testing.T) {
	f := newInflight()
	f.done("never-opened")
	if got := f.count(""); got != 0 {
		t.Errorf("count = %d, want 0", got)
	}
}

func TestInflight_IsRaceFree(t *testing.T) {
	f := newInflight()
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := strconv.Itoa(i)
			f.open(id)
			f.count(id)
			f.done(id)
		}(i)
	}
	wg.Wait()
	if got := f.count(""); got != 0 {
		t.Errorf("count = %d after all closed, want 0", got)
	}
}
