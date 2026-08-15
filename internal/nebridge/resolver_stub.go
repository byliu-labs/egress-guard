package nebridge

import (
	"github.com/byliu-labs/egress-guard/internal/procid"
	"github.com/byliu-labs/egress-guard/internal/signature"
)

// StubResolver returns a fixed identity. Err forces resolution to fail.
type StubResolver struct {
	Proc procid.ProcInfo
	Sig  signature.SignedIdentity
	Err  error
}

func (s StubResolver) Resolve([32]byte) (procid.ProcInfo, signature.SignedIdentity, error) {
	if s.Err != nil {
		return procid.ProcInfo{}, signature.SignedIdentity{}, s.Err
	}
	return s.Proc, s.Sig, nil
}
