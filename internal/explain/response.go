package explain

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/byliu-labs/egress-guard/internal/catalog"
)

type chatResponse struct {
	Choices []struct {
		Message chatMessage `json:"message"`
	} `json:"choices"`
}

type modelPayload struct {
	Explanation string   `json:"explanation"`
	Confidence  string   `json:"confidence"`
	Evidence    string   `json:"evidence"`
	Never       []string `json:"never,omitempty"`
}

// parseResponseBody validates the model response. Anything other than a clean,
// evidenced high/medium answer is unusable and must fall back to human review.
func parseResponseBody(raw []byte) (Explanation, error) {
	var resp chatResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return Explanation{}, fmt.Errorf("explain: response is not valid chat-completions JSON: %w", err)
	}
	if len(resp.Choices) == 0 {
		return Explanation{}, fmt.Errorf("explain: response has no choices")
	}
	var payload modelPayload
	content := resp.Choices[0].Message.Content
	if err := json.Unmarshal([]byte(content), &payload); err != nil {
		return Explanation{}, fmt.Errorf("explain: model content is not the expected JSON payload: %w", err)
	}
	if strings.TrimSpace(payload.Explanation) == "" {
		return Explanation{}, fmt.Errorf("explain: model returned an empty explanation")
	}
	if strings.TrimSpace(payload.Evidence) == "" {
		return Explanation{}, fmt.Errorf("explain: model returned no evidence")
	}
	var confidence catalog.Confidence
	switch strings.ToLower(strings.TrimSpace(payload.Confidence)) {
	case "high":
		confidence = catalog.ConfidenceHigh
	case "medium":
		confidence = catalog.ConfidenceMedium
	default:
		return Explanation{}, fmt.Errorf("explain: model confidence %q is not usable", payload.Confidence)
	}
	return New(payload.Explanation, confidence, payload.Evidence, payload.Never), nil
}
