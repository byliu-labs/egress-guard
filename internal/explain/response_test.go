package explain

import (
	"strings"
	"testing"

	"github.com/byliu-labs/egress-guard/internal/catalog"
)

func chatJSON(content string) []byte {
	escaped := strings.ReplaceAll(content, `"`, `\"`)
	return []byte(`{"choices":[{"message":{"role":"assistant","content":"` + escaped + `"}}]}`)
}

func TestParseResponseBody_HighConfidence(t *testing.T) {
	raw := chatJSON(`{"explanation":"Sparkle is a common macOS auto-update framework.","confidence":"high","evidence":"team_id matches the published Sparkle framework signature.","never":["should never open a listening socket"]}`)
	got, err := parseResponseBody(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Confidence != catalog.ConfidenceHigh {
		t.Fatalf("want ConfidenceHigh, got %v", got.Confidence)
	}
	if !got.ModelOpinion {
		t.Fatal("parsed Explanation must have ModelOpinion=true")
	}
	if len(got.Never) != 1 {
		t.Fatalf("expected the never caveat to round-trip, got %v", got.Never)
	}
}

func TestParseResponseBody_LowConfidenceIsAnError(t *testing.T) {
	raw := chatJSON(`{"explanation":"Not sure what this is.","confidence":"low","evidence":"no matching known vendor"}`)
	_, err := parseResponseBody(raw)
	if err == nil {
		t.Fatal(`a "low" confidence must be rejected as an error, not returned as a usable Explanation`)
	}
}

func TestParseResponseBody_MissingEvidenceIsAnError(t *testing.T) {
	raw := chatJSON(`{"explanation":"Looks fine.","confidence":"high","evidence":""}`)
	_, err := parseResponseBody(raw)
	if err == nil {
		t.Fatal("an explanation with no evidence must be rejected")
	}
}

func TestParseResponseBody_MalformedContentIsAnError(t *testing.T) {
	raw := []byte(`{"choices":[{"message":{"role":"assistant","content":"not json at all"}}]}`)
	_, err := parseResponseBody(raw)
	if err == nil {
		t.Fatal("malformed model content must be rejected, not partially parsed")
	}
}
