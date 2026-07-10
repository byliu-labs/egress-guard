// Package signature verifies a binary's code signature. On darwin it parses
// `codesign -dv --verify` output. Non-darwin builds get an unsupported stub
// (egress-guard's daemon is macOS-only; see issue #11 for Linux via
// OpenSnitch). Tests use Stub for deterministic results.
package signature

// SignedIdentity is the trust evidence for a binary.
type SignedIdentity struct {
	Valid    bool
	TeamID   string // darwin: Apple Developer Team ID
	BundleID string // darwin: bundle ID (e.g. com.apple.Safari)
}

type Verifier interface {
	Verify(exe string) (SignedIdentity, error)
}

// Default returns the platform implementation.
func Default() Verifier {
	return defaultVerifier()
}

// unsupported is the placeholder used on non-darwin builds.
type unsupported struct{}

func (unsupported) Verify(string) (SignedIdentity, error) {
	return SignedIdentity{Valid: false}, nil
}
