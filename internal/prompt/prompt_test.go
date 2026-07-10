package prompt

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/byliu-labs/egress-guard/internal/procid"
)

func TestDecide_AllowOncePassesOnce(t *testing.T) {
	d := New(Options{Notifier: &StaticNotifier{A: ActionAllowOnce}})
	got := d.Decide(context.Background(), Request{
		Proc: procid.ProcInfo{PID: 1}, Host: "foo.com", RegDom: "foo.com",
	})
	if got != Allow {
		t.Errorf("got %v, want Allow", got)
	}
}

func TestDecide_DenyAlwaysCallsAddDeny(t *testing.T) {
	rec := &recordingWriter{}
	d := New(Options{Notifier: &StaticNotifier{A: ActionDenyAlways}, AlwaysWriter: rec})
	got := d.Decide(context.Background(), Request{
		Proc: procid.ProcInfo{PID: 1}, Host: "api.bad.com", RegDom: "bad.com",
	})
	if got != Deny {
		t.Errorf("got %v, want Deny", got)
	}
	if rec.allowCalls != 0 {
		t.Errorf("AddAllow calls = %d, want 0", rec.allowCalls)
	}
	if rec.denyCalls != 1 {
		t.Errorf("AddDeny calls = %d, want 1", rec.denyCalls)
	}
	if rec.lastDeny != "bad.com" {
		t.Errorf("AddDeny called with %q, want %q (registered domain, not host)", rec.lastDeny, "bad.com")
	}
}

func TestDecide_AllowAlwaysCallsAddAllow(t *testing.T) {
	rec := &recordingWriter{}
	d := New(Options{Notifier: &StaticNotifier{A: ActionAllowAlways}, AlwaysWriter: rec})
	got := d.Decide(context.Background(), Request{
		Proc: procid.ProcInfo{PID: 1}, Host: "api.github.com", RegDom: "github.com",
	})
	if got != Allow {
		t.Errorf("got %v, want Allow", got)
	}
	if rec.allowCalls != 1 {
		t.Errorf("AddAllow calls = %d, want 1", rec.allowCalls)
	}
	if rec.lastAllow != "github.com" {
		t.Errorf("AddAllow called with %q, want %q (registered domain, not host)", rec.lastAllow, "github.com")
	}
}

func TestDecide_TimeoutFallsBackToDeny(t *testing.T) {
	d := New(Options{Notifier: TimeoutNotifier{}, Timeout: 50 * time.Millisecond})
	got := d.Decide(context.Background(), Request{
		Proc: procid.ProcInfo{PID: 1}, Host: "x.com", RegDom: "x.com",
	})
	if got != Deny {
		t.Errorf("timeout decide = %v, want Deny", got)
	}
}

// recordingWriter captures AddAllow/AddDeny calls so tests can assert the
// decider routed the user's action to the right writer method with the
// right argument.
type recordingWriter struct {
	mu                    sync.Mutex
	allowCalls, denyCalls int
	lastAllow, lastDeny   string
	err                   error
}

func (r *recordingWriter) AddAllow(regdom string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.allowCalls++
	r.lastAllow = regdom
	return r.err
}

func (r *recordingWriter) AddDeny(regdom string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.denyCalls++
	r.lastDeny = regdom
	return r.err
}

type recordingLogger struct {
	mu   sync.Mutex
	msgs []string
}

func (r *recordingLogger) Errorf(format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.msgs = append(r.msgs, fmt.Sprintf(format, args...))
}

func (r *recordingLogger) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.msgs))
	copy(out, r.msgs)
	return out
}

// TestDecide_AlwaysWriterErrorReachesLogger — when AlwaysWriter.AddAllow
// or AddDeny return an error, CoreDecider must surface it via Options.Logger
// instead of swallowing with `_`. Wired in cli.Start so persistence failures
// (disk full, perm denied) appear in the daemon log.
func TestDecide_AlwaysWriterErrorReachesLogger(t *testing.T) {
	for _, tc := range []struct {
		name   string
		action Action
		want   string
	}{
		{"allow-always", ActionAllowAlways, "AddAllow"},
		{"deny-always", ActionDenyAlways, "AddDeny"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logger := &recordingLogger{}
			writer := &recordingWriter{err: errors.New("disk full")}
			d := New(Options{
				Notifier:     &StaticNotifier{A: tc.action},
				AlwaysWriter: writer,
				Logger:       logger,
			})
			d.Decide(context.Background(), Request{
				Proc: procid.ProcInfo{PID: 1}, Host: "x.com", RegDom: "x.com",
			})
			msgs := logger.snapshot()
			if len(msgs) != 1 {
				t.Fatalf("Logger.Errorf calls = %d, want 1 (%v)", len(msgs), msgs)
			}
			if !contains(msgs[0], tc.want) || !contains(msgs[0], "disk full") {
				t.Errorf("logged %q, want substring %q + %q", msgs[0], tc.want, "disk full")
			}
		})
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
