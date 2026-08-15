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
