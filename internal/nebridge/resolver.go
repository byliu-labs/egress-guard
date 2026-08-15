package nebridge

import (
	"github.com/byliu-labs/egress-guard/internal/procid"
	"github.com/byliu-labs/egress-guard/internal/signature"
)

// IdentityResolver recovers the process and code-signature identity associated
// with an NEFilter audit token.
type IdentityResolver interface {
	Resolve(auditToken [32]byte) (procid.ProcInfo, signature.SignedIdentity, error)
}

// SystemResolver resolves an NEFilter audit token to process and signature
// identity. Darwin uses libbsm and libproc; other platforms fail closed.
type SystemResolver struct {
	Sig signature.Verifier
}

// NewSystemResolver returns the platform identity resolver used by the bridge.
func NewSystemResolver(verifier signature.Verifier) *SystemResolver {
	return &SystemResolver{Sig: verifier}
}
