package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/byliu-labs/egress-guard/internal/decisionlog"
)

func TestRenderEntry_FlowRecordIsReadable(t *testing.T) {
	e := decisionlog.Entry{
		Timestamp:  "2026-08-16T10:00:00Z",
		Kind:       decisionlog.KindFlow,
		ConnID:     "0123456789abcdef",
		Exe:        "/usr/bin/curl",
		Host:       "pypi.org",
		BytesUp:    4096,
		BytesDown:  1048576,
		DurationMS: 2500,
	}
	got := renderEntry(e)
	for _, want := range []string{"flow", "pypi.org", "curl", "4.0K", "1.0M", "2.5s"} {
		if !strings.Contains(got, want) {
			t.Errorf("rendering %q is missing %q", got, want)
		}
	}
	if strings.Contains(got, "{") {
		t.Errorf("flow record rendered as raw JSON: %s", got)
	}
}

func TestDecisionLogLineRenderer_RendersJSONL(t *testing.T) {
	var out bytes.Buffer
	w := newDecisionLogLineRenderer(&out)
	e := decisionlog.Entry{
		Timestamp: "2026-08-16T10:00:00Z",
		Decision:  decisionlog.DecisionAllow,
		Action:    "allow",
		Host:      "pypi.org",
		Exe:       "/usr/bin/curl",
	}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(append(b, '\n')); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got := out.String()
	for _, want := range []string{"allow", "pypi.org", "curl"} {
		if !strings.Contains(got, want) {
			t.Errorf("rendered line %q is missing %q", got, want)
		}
	}
	if strings.Contains(got, "{") {
		t.Errorf("decision record rendered as raw JSON: %s", got)
	}
}

func TestDecisionLogLineRenderer_BuffersSplitLine(t *testing.T) {
	var out bytes.Buffer
	w := newDecisionLogLineRenderer(&out)
	e := decisionlog.Entry{
		Timestamp: "2026-08-16T10:00:00Z",
		Kind:      decisionlog.KindFlow,
		Host:      "pypi.org",
		Exe:       "/usr/bin/curl",
		BytesUp:   4096,
		BytesDown: 8192,
	}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	line := append(b, '\n')
	split := len(line) / 2
	if _, err := w.Write(line[:split]); err != nil {
		t.Fatalf("first Write: %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("partial line rendered early: %q", out.String())
	}
	if _, err := w.Write(line[split:]); err != nil {
		t.Fatalf("second Write: %v", err)
	}
	got := out.String()
	for _, want := range []string{"flow", "pypi.org", "curl", "4.0K", "8.0K"} {
		if !strings.Contains(got, want) {
			t.Errorf("rendered split line %q is missing %q", got, want)
		}
	}
	if strings.Contains(got, "{") {
		t.Errorf("split flow record rendered as raw JSON: %s", got)
	}
}
