//go:build !darwin

package nebridge

import (
	"fmt"

	"github.com/byliu-labs/egress-guard/internal/procid"
	"github.com/byliu-labs/egress-guard/internal/signature"
)

func (r *SystemResolver) Resolve([32]byte) (procid.ProcInfo, signature.SignedIdentity, error) {
	return procid.ProcInfo{}, signature.SignedIdentity{}, fmt.Errorf("nebridge: system identity resolution is unavailable")
}
