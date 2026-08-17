package decisionlog

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestEntry_FlowFieldsRoundTrip(t *testing.T) {
	e := Entry{
		Timestamp:  "2026-08-16T10:00:00Z",
		Kind:       KindFlow,
		ConnID:     "0123456789abcdef",
		BytesUp:    4096,
		BytesDown:  1048576,
		DurationMS: 2500,
	}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	var got Entry
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.ConnID != e.ConnID || got.BytesUp != e.BytesUp ||
		got.BytesDown != e.BytesDown || got.DurationMS != e.DurationMS || got.Kind != KindFlow {
		t.Fatalf("round-trip lost data: %+v", got)
	}
}

func TestEntry_ZeroByteFlowSerializesCounts(t *testing.T) {
	e := Entry{
		Timestamp: "2026-08-16T10:00:00Z",
		Kind:      KindFlow,
		ConnID:    "0123456789abcdef",
	}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"bytes_up":0`, `"bytes_down":0`, `"duration_ms":0`} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("zero-byte flow omitted %s: %s", want, b)
		}
	}
}

// A decision record must serialize exactly as it does today, so existing
// blocked.log consumers keep parsing after this change.
func TestEntry_DecisionSerializationUnchanged(t *testing.T) {
	e := Entry{Timestamp: "2026-08-16T10:00:00Z", Decision: DecisionAllow, Action: "allow", Host: "pypi.org"}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	for _, absent := range []string{"kind", "conn_id", "bytes_up", "bytes_down", "duration_ms"} {
		if strings.Contains(string(b), absent) {
			t.Fatalf("unset field %q leaked into a decision record: %s", absent, b)
		}
	}
}
