package telemetry

import (
	"context"
	"time"

	"github.com/byliu-labs/egress-guard/internal/catalog"
)

// RatifyWriter mirrors the ratification hook structurally.
type RatifyWriter interface {
	Ratify(e catalog.Entry) error
}

// ReportingRatifyWriter wraps a RatifyWriter with opt-in report delivery.
type ReportingRatifyWriter struct {
	Inner       RatifyWriter
	Cfg         *Config
	Sender      Sender
	SendTimeout time.Duration
}

func (r ReportingRatifyWriter) Ratify(e catalog.Entry) error {
	if err := r.Inner.Ratify(e); err != nil {
		return err
	}
	if r.Cfg == nil || !r.Cfg.Enabled || r.Sender == nil {
		return nil
	}
	host, verdict, ok := verdictFor(e)
	if !ok {
		return nil
	}
	report := NewReport(r.Cfg.InstallUUID, e.Identity, host, verdict)
	timeout := r.SendTimeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		_ = r.Sender.Send(ctx, report)
	}()
	return nil
}

func verdictFor(e catalog.Entry) (host, verdict string, ok bool) {
	if len(e.Never) > 0 {
		return e.Never[len(e.Never)-1], "deny", true
	}
	if len(e.ExpectedDestinations) > 0 {
		return e.ExpectedDestinations[len(e.ExpectedDestinations)-1].Host, "allow", true
	}
	return "", "", false
}
