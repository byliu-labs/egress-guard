package explain

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/byliu-labs/egress-guard/internal/catalog"
)

func TestBuildRequestBody_SendsOnlyIdentityAndHost(t *testing.T) {
	cfg := Config{Model: "test-model"}
	id := catalog.Identity{ExeBasename: "updater", TeamID: "ABCDE12345", BundleID: "com.example.updater", SignedRequired: true}
	b, err := buildRequestBody(cfg, id, "updates.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var req chatRequest
	if err := json.Unmarshal(b, &req); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}
	if len(req.Messages) != 2 {
		t.Fatalf("expected system+user messages, got %d", len(req.Messages))
	}
	user := req.Messages[1].Content
	for _, want := range []string{"updater", "ABCDE12345", "com.example.updater", "updates.example.com"} {
		if !strings.Contains(user, want) {
			t.Fatalf("expected user message to contain %q, got: %s", want, user)
		}
	}
	if strings.Contains(user, "argv") || strings.Contains(user, "cwd") {
		t.Fatal("request body must never mention argv/cwd: identity + host only")
	}
}
