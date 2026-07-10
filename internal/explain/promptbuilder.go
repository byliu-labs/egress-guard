package explain

import (
	"encoding/json"
	"fmt"

	"github.com/byliu-labs/egress-guard/internal/catalog"
)

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model    string        `json:"model,omitempty"`
	Messages []chatMessage `json:"messages"`
}

const systemPrompt = `You explain unfamiliar outbound network connections to a non-expert user of a firewall tool called egress-guard. You will be given a process identity and a destination hostname, and nothing else. Reply with a single JSON object, no prose outside it, with exactly these fields: {"explanation":"one or two plain-English sentences","confidence":"high or medium only","evidence":"the specific fact behind your confidence","never":["optional list of things this software should never do"]}. If you cannot form a confident explanation, return confidence "low"; the caller treats that as no usable opinion.`

// buildRequestBody renders the outbound request. Only id and host are sent:
// no argv, cwd, PID, decision-log history, or traffic payload.
func buildRequestBody(cfg Config, id catalog.Identity, host string) ([]byte, error) {
	user := fmt.Sprintf(
		"Process identity: exe_basename=%q team_id=%q bundle_id=%q signed_required=%v\nDestination host: %q",
		id.ExeBasename, id.TeamID, id.BundleID, id.SignedRequired, host,
	)
	req := chatRequest{
		Model: cfg.Model,
		Messages: []chatMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: user},
		},
	}
	b, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("explain: marshal request: %w", err)
	}
	return b, nil
}
