//go:build darwin

package prompt

import (
	"context"
	"os/exec"
	"testing"
	"time"

	"github.com/byliu-labs/egress-guard/internal/procid"
)

func TestDarwin_NotifyParsesScript(t *testing.T) {
	// Skip if osascript is not available (e.g., non-macOS CI).
	if _, err := exec.LookPath("osascript"); err != nil {
		t.Skip("osascript not found in PATH")
	}

	// Set test override so we don't actually pop dialogs.
	t.Setenv("EGRESS_GUARD_OSASCRIPT_RESULT", "Allow once")

	dn := &darwinNotifier{}
	req := Request{
		Proc: procid.ProcInfo{
			PID:  12345,
			Comm: "curl",
		},
		Host:       "example.com",
		RegDom:     "example.com",
		ReceivedAt: time.Now(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	action, err := dn.Notify(ctx, req)
	if err != nil {
		t.Fatalf("Notify failed: %v", err)
	}

	if action != ActionAllowOnce {
		t.Errorf("expected ActionAllowOnce, got %v", action)
	}
}

func TestParseDarwinChoice(t *testing.T) {
	tests := []struct {
		choice   string
		expected Action
	}{
		{"Allow once", ActionAllowOnce},
		{"Allow always", ActionAllowAlways},
		{"Deny always", ActionDenyAlways},
		{"Deny", ActionDeny}, // default button
		{"", ActionDeny},     // empty string defaults to deny
		{"unknown", ActionDeny},
	}

	for _, tt := range tests {
		t.Run(tt.choice, func(t *testing.T) {
			got := parseDarwinChoice(tt.choice)
			if got != tt.expected {
				t.Errorf("parseDarwinChoice(%q) = %v, want %v", tt.choice, got, tt.expected)
			}
		})
	}
}

func TestEscapeAS(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"simple", "simple"},
		{`quote"test`, `quote\"test`},
		{`back\slash`, `back\\slash`},
		{`both"and\back`, `both\"and\\back`},
		{`already\"escaped`, `already\\\"escaped`},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := escapeAS(tt.input)
			if got != tt.expected {
				t.Errorf("escapeAS(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestDialogBody(t *testing.T) {
	tests := []struct {
		name   string
		req    Request
		expect string
	}{
		{
			"normal connection, no catalog/opinion context",
			Request{
				Proc:   procid.ProcInfo{Comm: "curl"},
				Host:   "api.example.com",
				RegDom: "example.com",
			},
			"curl wants to connect to api.example.com.\n" +
				"No catalog match and no model opinion -- reviewing based on process and destination only.\n" +
				"Allow this destination?",
		},
		{
			"burst mode",
			Request{
				Proc:   procid.ProcInfo{Comm: "python"},
				RegDom: "(burst)",
			},
			"python is making many new outbound connections. Review or deny all?",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := dialogBody(tt.req)
			if got != tt.expect {
				t.Errorf("dialogBody() = %q, want %q", got, tt.expect)
			}
		})
	}
}
