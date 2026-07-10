package explain_test

import (
	"testing"
	"time"

	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/explain"
	"github.com/byliu-labs/egress-guard/internal/procid"
	"github.com/byliu-labs/egress-guard/internal/prompt"
)

func TestExplainerPlugsIntoPromptAdvisorySlot(t *testing.T) {
	exp := explain.New("looks like a CLI package manager", catalog.ConfidenceMedium, "well-known bundle id", []string{"should never phone home with credentials"})

	req := prompt.Request{
		Proc:       procid.ProcInfo{Exe: "/usr/local/bin/some-tool"},
		Host:       "registry.example.com",
		RegDom:     "example.com",
		ReceivedAt: time.Now(),
		Opinion:    &exp,
	}

	if req.Opinion == nil || !req.Opinion.ModelOpinion {
		t.Fatal("expected the advisory slot to carry a model-opinion Explanation")
	}
}

func TestPromptRequestWorksWithNilOpinion(t *testing.T) {
	req := prompt.Request{
		Proc:       procid.ProcInfo{Exe: "/usr/local/bin/some-tool"},
		Host:       "registry.example.com",
		RegDom:     "example.com",
		ReceivedAt: time.Now(),
	}
	if req.Opinion != nil {
		t.Fatal("zero-value Request.Opinion must be nil")
	}
}
