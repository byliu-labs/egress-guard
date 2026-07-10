//go:build !darwin

package persist

import (
	"errors"

	"github.com/byliu-labs/egress-guard/internal/procid"
)

func classify(procid.ProcInfo) (SourceKind, string, error) {
	return KindUnknown, "", errors.New("persist: unsupported platform")
}
