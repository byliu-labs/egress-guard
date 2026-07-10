// Package procid identifies the process that originated a TCP connection.
// darwin uses lsof + libproc (proc_pidpath/proc_pidinfo via syscall). Non-
// darwin builds get an unsupported stub (egress-guard's daemon is macOS-
// only; see issue #11 for Linux via OpenSnitch). Tests use the in-memory
// Stub.
package procid

import (
	"errors"
	"net"
)

// ProcInfo is what the daemon needs to make trust decisions.
type ProcInfo struct {
	PID   int
	PPID  int
	Exe   string   // absolute path to executable (or empty if unknown)
	Argv  []string // argv as observed (best-effort)
	Cwd   string   // working directory (best-effort)
	Comm  string   // basename of exe (or kernel-reported short name)
	PComm string   // parent process basename
}

// Lookup recovers ProcInfo for the local end of a connection.
type Lookup interface {
	LookupConn(conn net.Conn) (ProcInfo, error)
}

// Default returns the platform implementation.
func Default() Lookup {
	return defaultLookup()
}

// unsupported is the placeholder Lookup for non-darwin builds.
type unsupported struct{}

func (unsupported) LookupConn(net.Conn) (ProcInfo, error) {
	return ProcInfo{}, errors.New("procid: unsupported platform")
}
