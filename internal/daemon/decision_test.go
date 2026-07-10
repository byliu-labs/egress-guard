package daemon

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/byliu-labs/egress-guard/internal/allowlist"
	"github.com/byliu-labs/egress-guard/internal/decisionlog"
	"github.com/byliu-labs/egress-guard/internal/exempt"
	"github.com/byliu-labs/egress-guard/internal/procid"
	"github.com/byliu-labs/egress-guard/internal/prompt"
	"github.com/byliu-labs/egress-guard/internal/signature"
)

// stubKernel returns canned dest IP/port. Used by both this file and
// decision_branches_test.go.
type stubKernel struct {
	ip   net.IP
	port int
}

func (s *stubKernel) Install(int) error                          { return nil }
func (s *stubKernel) Uninstall() error                           { return nil }
func (s *stubKernel) IsInstalled() (bool, error)                 { return true, nil }
func (s *stubKernel) OriginalDest(net.Conn) (net.IP, int, error) { return s.ip, s.port, nil }

// stubAlwaysAllow / stubAlwaysDeny are deterministic prompt.Deciders for tests.
type stubAlwaysAllow struct{}

func (stubAlwaysAllow) Decide(context.Context, prompt.Request) prompt.Decision {
	return prompt.Allow
}

type stubAlwaysDeny struct{}

func (stubAlwaysDeny) Decide(context.Context, prompt.Request) prompt.Decision {
	return prompt.Deny
}

// newTestDaemon constructs a daemon with the v0.2 pipeline wired up against
// stubs. Kept for future splice-level tests; the branch-level coverage lives
// in decision_branches_test.go.
func newTestDaemon(t *testing.T, dec prompt.Decider, exemptResult bool) (*Daemon, *decisionlog.Writer, string) {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "log.jsonl")
	bl, _ := decisionlog.Open(logPath)

	a := allowlist.New(allowlist.Config{
		Defaults: allowlist.Layer{Allow: []string{"allow.example"}},
	})

	exemptStub := &exemptStubCatalog{result: exemptResult}

	d, err := New(Options{
		Listen:    "127.0.0.1:0",
		Kernel:    &stubKernel{ip: net.ParseIP("203.0.113.10"), port: 443},
		Allow:     a,
		Log:       bl,
		ProcID:    procid.NewStub(),
		Signature: signature.NewStub(),
		Exempt:    exemptStub.unwrap(),
		Prompt:    dec,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return d, bl, logPath
}

// exemptStubCatalog wraps a *exempt.Catalog whose IsExempt is deterministic
// for the splice-level test scaffold below. Real branch coverage uses
// LoadFromString directly.
type exemptStubCatalog struct{ result bool }

func (e *exemptStubCatalog) unwrap() *exempt.Catalog {
	if e.result {
		c, _ := exempt.LoadFromString(`
[[macos]]
exe_basename = "test-exempt"
team_id      = "TEST"
`)
		return c
	}
	c, _ := exempt.LoadDefault()
	return c
}

func TestDecide_ExemptProcessSplices(t *testing.T) {
	// Skipped scaffold — full splice E2E is covered in Phase 11. Branch-level
	// coverage of the decision tree lives in decision_branches_test.go.
	t.Skip("splice path covered in integration tests")
	_ = time.Second
	_ = newTestDaemon
	_ = stubAlwaysAllow{}
	_ = stubAlwaysDeny{}
}
