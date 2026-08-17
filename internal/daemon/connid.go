package daemon

import (
	"crypto/rand"
	"encoding/hex"
)

// newConnID returns a per-connection correlation ID linking a decision record
// to its close-time flow record. It is random, never reused, and derived from
// nothing about the connection; it carries no identity and no destination.
// On the vanishingly unlikely rand failure it returns the empty string, which
// callers treat as "uncorrelated" rather than crashing the daemon.
func newConnID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	return hex.EncodeToString(b[:])
}
