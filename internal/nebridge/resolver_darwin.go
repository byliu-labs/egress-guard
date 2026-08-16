//go:build darwin

package nebridge

/*
#cgo LDFLAGS: -lbsm -framework CoreFoundation -framework Security
#include <bsm/libbsm.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/SecCode.h>
#include <limits.h>
#include <mach/mach.h>
#include <mach/task_info.h>
#include <stdint.h>
#include <string.h>

static OSStatus audit_token_path(const uint8_t token[32], char *path,
	uint32_t path_len, pid_t *pid, int *pidversion) {
	audit_token_t audit;
	memcpy(&audit, token, sizeof(audit));
	*pid = audit_token_to_pid(audit);
	*pidversion = audit_token_to_pidversion(audit);

	CFDataRef data = CFDataCreate(kCFAllocatorDefault, token, sizeof(audit));
	if (data == NULL) {
		return -1;
	}
	const void *keys[] = { kSecGuestAttributeAudit };
	const void *values[] = { data };
	CFDictionaryRef attributes = CFDictionaryCreate(kCFAllocatorDefault,
		keys, values, 1, &kCFTypeDictionaryKeyCallBacks,
		&kCFTypeDictionaryValueCallBacks);
	CFRelease(data);
	if (attributes == NULL) {
		return -1;
	}

	SecCodeRef guest = NULL;
	OSStatus status = SecCodeCopyGuestWithAttributes(NULL, attributes,
		kSecCSDefaultFlags, &guest);
	CFRelease(attributes);
	if (status != 0) {
		return status;
	}

	CFURLRef url = NULL;
	status = SecCodeCopyPath(guest, kSecCSDefaultFlags, &url);
	CFRelease(guest);
	if (status != 0) {
		return status;
	}
	Boolean copied = CFURLGetFileSystemRepresentation(url, true,
		(UInt8 *)path, path_len);
	CFRelease(url);
	return copied ? 0 : -1;
}

static kern_return_t current_process_audit_token(uint8_t token[32]) {
	audit_token_t audit;
	mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
	kern_return_t status = task_info(mach_task_self(), TASK_AUDIT_TOKEN,
		(task_info_t)&audit, &count);
	if (status == KERN_SUCCESS) {
		memcpy(token, &audit, sizeof(audit));
	}
	return status;
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
	path := make([]byte, int(C.PATH_MAX))
	var cPID C.pid_t
	var cPIDVersion C.int
	status := C.audit_token_path(
		(*C.uint8_t)(unsafe.Pointer(&auditToken[0])),
		(*C.char)(unsafe.Pointer(&path[0])),
		C.uint32_t(len(path)),
		&cPID,
		&cPIDVersion,
	)
	pid := int(cPID)
	if pid <= 0 {
		return procid.ProcInfo{}, signature.SignedIdentity{}, fmt.Errorf("nebridge: audit token has invalid pid %d", pid)
	}
	if status != 0 {
		return procid.ProcInfo{}, signature.SignedIdentity{}, fmt.Errorf(
			"nebridge: Security.framework rejected audit token for pid %d pidversion %d: OSStatus %d",
			pid, int(cPIDVersion), int32(status),
		)
	}
	exe := C.GoString((*C.char)(unsafe.Pointer(&path[0])))
	if exe == "" {
		return procid.ProcInfo{}, signature.SignedIdentity{}, fmt.Errorf("nebridge: audit-token guest for pid %d returned an empty path", pid)
	}

	// Security.framework binds the executable path to the full live audit token,
	// including pidversion. The verifier remains path-based; it does not claim to
	// extract signing fields from the dynamic SecCodeRef.
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

// currentProcessAuditToken returns a kernel-issued token for the resolver's
// Darwin self-tests. Production receives tokens from NEFilter flow metadata.
func currentProcessAuditToken() ([32]byte, error) {
	var token [32]byte
	status := C.current_process_audit_token((*C.uint8_t)(unsafe.Pointer(&token[0])))
	if status != C.KERN_SUCCESS {
		return token, fmt.Errorf("nebridge: task_info(TASK_AUDIT_TOKEN): %d", int(status))
	}
	return token, nil
}
