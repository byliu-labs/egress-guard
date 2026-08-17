package daemon

import (
	"context"
	"net"

	"github.com/byliu-labs/egress-guard/internal/allowlist"
	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/decisionlog"
	"github.com/byliu-labs/egress-guard/internal/kernel"
	"github.com/byliu-labs/egress-guard/internal/procid"
	"github.com/byliu-labs/egress-guard/internal/prompt"
	"github.com/byliu-labs/egress-guard/internal/signature"
)

type noopKernel struct{}

func (noopKernel) Install(int) error                          { return nil }
func (noopKernel) Uninstall() error                           { return nil }
func (noopKernel) IsInstalled() (bool, error)                 { return true, nil }
func (noopKernel) OriginalDest(net.Conn) (net.IP, int, error) { return nil, 0, nil }

var _ kernel.RulesInstaller = noopKernel{}

type promptProbe struct{ called bool }

func (p *promptProbe) Decide(context.Context, prompt.Request) prompt.Decision {
	p.called = true
	return prompt.Deny
}

// DecideForTest runs the real branch decision path for an observed executable.
// It is an internal acceptance-test probe, not a product API.
func DecideForTest(cat *catalog.Catalog, store PendingRecorder, hasher *procid.ExeHasher, exe, host string) (allowed bool, reason string, prompted bool, err error) {
	spy := &promptProbe{}
	d, err := New(Options{
		Listen:    "127.0.0.1:0",
		Kernel:    noopKernel{},
		Allow:     allowlist.New(allowlist.Config{}),
		Log:       &decisionlog.Writer{},
		ProcID:    procid.NewStub(),
		Signature: signature.NewStub(),
		Catalog:   cat,
		Prompt:    spy,
		Pending:   store,
	})
	if err != nil {
		return false, "", false, err
	}
	d.hasher = hasher
	outcome, entry := d.decideBranch(host, nil, procid.ProcInfo{PID: 1, Exe: exe, Comm: "tool"}, signature.SignedIdentity{})
	return outcome == outcomeAllow, entry.Reason, spy.called, nil
}
