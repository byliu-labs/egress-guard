package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// Sender delivers one Report to the maintainer review queue intake.
type Sender interface {
	Send(ctx context.Context, r Report) error
}

// HTTPSender POSTs a Report as JSON to a fixed endpoint.
type HTTPSender struct {
	Endpoint string
	Client   *http.Client
}

func (s HTTPSender) Send(ctx context.Context, r Report) error {
	client := s.Client
	if client == nil {
		client = http.DefaultClient
	}
	b, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("telemetry: marshal report: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.Endpoint, bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("telemetry: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("telemetry: send to %s: %w", s.Endpoint, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("telemetry: send to %s: status %d", s.Endpoint, resp.StatusCode)
	}
	return nil
}
