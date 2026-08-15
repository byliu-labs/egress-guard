package nebridge

import (
	"fmt"

	"github.com/byliu-labs/egress-guard/internal/procid"
	"github.com/byliu-labs/egress-guard/internal/signature"
)

// IdentityResolver recovers the process and code-signature identity associated
// with an NEFilter audit token.
type IdentityResolver interface {
	Resolve(auditToken [32]byte) (procid.ProcInfo, signature.SignedIdentity, error)
}

// NewSystemResolver returns the platform identity resolver used by the bridge.
// Task 7 replaces this fail-closed placeholder with Darwin audit-token lookup.
func NewSystemResolver(verifier signature.Verifier) IdentityResolver {
	return systemResolver{verifier: verifier}
}

type systemResolver struct {
	// verifier is retained for Task 7's Darwin audit-token implementation.
	verifier signature.Verifier
}

func (r systemResolver) Resolve([32]byte) (procid.ProcInfo, signature.SignedIdentity, error) {
	return procid.ProcInfo{}, signature.SignedIdentity{}, fmt.Errorf("nebridge: system identity resolution is unavailable")
}
