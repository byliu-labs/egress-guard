package telemetry

import (
	"context"
	"testing"
	"time"

	"github.com/byliu-labs/egress-guard/internal/catalog"
)

type fakeInner struct {
	calls []catalog.Entry
	err   error
}

func (f *fakeInner) Ratify(e catalog.Entry) error {
	f.calls = append(f.calls, e)
	return f.err
}

type fakeSender struct {
	reports chan Report
}

func newFakeSender() *fakeSender {
	return &fakeSender{reports: make(chan Report, 4)}
}

func (f *fakeSender) Send(ctx context.Context, r Report) error {
	f.reports <- r
	return nil
}

func TestReportingRatifyWriter_EnabledSendsAllowReport(t *testing.T) {
	inner := &fakeInner{}
	sender := newFakeSender()
	cfg := &Config{Enabled: true, InstallUUID: "uuid-1"}
	w := ReportingRatifyWriter{Inner: inner, Cfg: cfg, Sender: sender, SendTimeout: time.Second}

	entry := catalog.Entry{
		Identity:             catalog.Identity{ExeBasename: "curl"},
		ExpectedDestinations: []catalog.Destination{{Host: "api.example.com", Why: "user ratified"}},
	}
	if err := w.Ratify(entry); err != nil {
		t.Fatalf("Ratify: %v", err)
	}
	if len(inner.calls) != 1 || inner.calls[0].Identity.ExeBasename != "curl" {
		t.Fatalf("inner.Ratify calls = %+v, want one call carrying the entry", inner.calls)
	}

	select {
	case r := <-sender.reports:
		if r.Host != "api.example.com" || r.Verdict != "allow" || r.InstallUUID != "uuid-1" {
			t.Fatalf("sent report = %+v, want host=api.example.com verdict=allow uuid=uuid-1", r)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no report sent within timeout")
	}
}

func TestReportingRatifyWriter_DenyAlwaysReportsDenyVerdict(t *testing.T) {
	inner := &fakeInner{}
	sender := newFakeSender()
	cfg := &Config{Enabled: true, InstallUUID: "uuid-1"}
	w := ReportingRatifyWriter{Inner: inner, Cfg: cfg, Sender: sender, SendTimeout: time.Second}

	entry := catalog.Entry{
		Identity: catalog.Identity{ExeBasename: "curl"},
		Never:    []string{"evil.example.com"},
	}
	if err := w.Ratify(entry); err != nil {
		t.Fatalf("Ratify: %v", err)
	}

	select {
	case r := <-sender.reports:
		if r.Host != "evil.example.com" || r.Verdict != "deny" {
			t.Fatalf("sent report = %+v, want host=evil.example.com verdict=deny", r)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no report sent within timeout")
	}
}

func TestReportingRatifyWriter_DisabledNeverSends(t *testing.T) {
	inner := &fakeInner{}
	sender := newFakeSender()
	cfg := &Config{Enabled: false, InstallUUID: "uuid-1"}
	w := ReportingRatifyWriter{Inner: inner, Cfg: cfg, Sender: sender, SendTimeout: time.Second}

	entry := catalog.Entry{
		Identity:             catalog.Identity{ExeBasename: "curl"},
		ExpectedDestinations: []catalog.Destination{{Host: "api.example.com"}},
	}
	if err := w.Ratify(entry); err != nil {
		t.Fatalf("Ratify: %v", err)
	}

	select {
	case r := <-sender.reports:
		t.Fatalf("sender.Send called while telemetry disabled: %+v", r)
	case <-time.After(300 * time.Millisecond):
	}
}

func TestReportingRatifyWriter_InnerErrorPropagatesAndSkipsSend(t *testing.T) {
	inner := &fakeInner{err: context.DeadlineExceeded}
	sender := newFakeSender()
	cfg := &Config{Enabled: true, InstallUUID: "uuid-1"}
	w := ReportingRatifyWriter{Inner: inner, Cfg: cfg, Sender: sender, SendTimeout: time.Second}

	entry := catalog.Entry{
		Identity:             catalog.Identity{ExeBasename: "curl"},
		ExpectedDestinations: []catalog.Destination{{Host: "api.example.com"}},
	}
	if err := w.Ratify(entry); err == nil {
		t.Fatal("Ratify: want error propagated from inner, got nil")
	}
	select {
	case r := <-sender.reports:
		t.Fatalf("sender.Send called despite inner.Ratify error: %+v", r)
	case <-time.After(300 * time.Millisecond):
	}
}
