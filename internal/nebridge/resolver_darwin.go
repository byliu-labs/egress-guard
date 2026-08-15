//go:build darwin

package nebridge

/*
#cgo LDFLAGS: -lbsm -lproc
#include <bsm/libbsm.h>
#include <libproc.h>
#include <stdint.h>
#include <string.h>

static pid_t audit_token_pid(const uint8_t token[32]) {
	audit_token_t audit;
	memcpy(&audit, token, sizeof(audit));
	return audit_token_to_pid(audit);
}
*/
import "C"

import (
	"fmt"
	"path/filepath"
	"unsafe"

	"github.com/byliu-labs/egress-guard/internal/procid"
	"github.com/byliu-labs/egress-guard/internal/signature"
)

// Resolve derives the process identity bound to an NEFilter audit token.
func (r *SystemResolver) Resolve(auditToken [32]byte) (procid.ProcInfo, signature.SignedIdentity, error) {
	pid := int(C.audit_token_pid((*C.uint8_t)(unsafe.Pointer(&auditToken[0]))))
	if pid <= 0 {
		return procid.ProcInfo{}, signature.SignedIdentity{}, fmt.Errorf("nebridge: audit token has invalid pid %d", pid)
	}

	path := make([]byte, int(C.PROC_PIDPATHINFO_MAXSIZE))
	if C.proc_pidpath(C.int(pid), unsafe.Pointer(&path[0]), C.uint32_t(len(path))) <= 0 {
		return procid.ProcInfo{}, signature.SignedIdentity{}, fmt.Errorf("nebridge: proc_pidpath(%d) failed", pid)
	}
	exe := C.GoString((*C.char)(unsafe.Pointer(&path[0])))
	if exe == "" {
		return procid.ProcInfo{}, signature.SignedIdentity{}, fmt.Errorf("nebridge: proc_pidpath(%d) returned an empty path", pid)
	}

	verifier := r.Sig
	if verifier == nil {
		verifier = signature.Default()
	}
	id, err := verifier.Verify(exe)
	if err != nil {
		return procid.ProcInfo{}, signature.SignedIdentity{}, fmt.Errorf("nebridge: verify %q: %w", exe, err)
	}
	return procid.ProcInfo{PID: pid, Exe: exe, Comm: filepath.Base(exe)}, id, nil
}
