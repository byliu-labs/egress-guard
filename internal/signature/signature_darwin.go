//go:build darwin

package signature

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"time"
)

// shelloutTimeout caps codesign invocations. Real-world codesign on a single
// binary is <100ms; 2s is a generous deadline that still prevents one stuck
// invocation from wedging the per-connection goroutine.
const shelloutTimeout = 2 * time.Second

func defaultVerifier() Verifier { return &darwinVerifier{} }

type darwinVerifier struct{}

var (
	reTeamID    = regexp.MustCompile(`(?m)^TeamIdentifier=(.+)$`)
	reBundleID  = regexp.MustCompile(`(?m)^Identifier=(.+)$`)
	reAuthority = regexp.MustCompile(`(?m)^Authority=(.+)$`)
)

func (d *darwinVerifier) Verify(exe string) (SignedIdentity, error) {
	// First, verify signature integrity (catches tampered binaries).
	// CombinedOutput captures the diagnostic message ("a sealed resource is
	// missing or invalid", etc.) so the daemon's log says *why* verification
	// failed, not just "exit status 1".
	ctx, cancel := context.WithTimeout(context.Background(), shelloutTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "codesign", "-v", "--", exe)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	if out, err := cmd.CombinedOutput(); err != nil {
		return SignedIdentity{Valid: false}, fmt.Errorf("codesign -v: %w (output: %s)", err, out)
	}

	// Signature is valid. Now extract identity details.
	// -dvv: display signature info (TeamID, BundleID) plus the Authority
	// chain (CN of each cert in the signing chain), which we need for the
	// Apple-system-binary normalization below.
	ctx2, cancel2 := context.WithTimeout(context.Background(), shelloutTimeout)
	defer cancel2()
	cmd = exec.CommandContext(ctx2, "codesign", "-dvv", "--", exe)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return SignedIdentity{Valid: false}, fmt.Errorf("codesign -dv: %w (output: %s)", err, out)
	}
	id := SignedIdentity{Valid: true}
	if m := reTeamID.FindStringSubmatch(string(out)); len(m) == 2 {
		id.TeamID = m[1]
	}
	if m := reBundleID.FindStringSubmatch(string(out)); len(m) == 2 {
		id.BundleID = m[1]
	}
	id = d.normalizeAppleSystemTeamID(out, id)
	return id, nil
}

// normalizeAppleSystemTeamID synthesizes TeamID="APPLE" for Apple's first-party
// system binaries (e.g. /usr/libexec/trustd, nsurlsessiond), which report
// TeamIdentifier="not set" because Apple itself has no third-party developer
// team id. The bundled catalog rules for these binaries use team_id="APPLE"
// as a synthetic marker; without normalization those rules would never match.
//
// Detection: Apple system binaries are signed by the chain
//
//	"Software Signing" -> "Apple Code Signing Certification Authority" -> "Apple Root CA"
//
// We require the first two Authority lines to be present.
func (d *darwinVerifier) normalizeAppleSystemTeamID(out []byte, id SignedIdentity) SignedIdentity {
	if id.TeamID != "" && id.TeamID != "not set" {
		return id
	}
	var hasSoftwareSigning, hasAppleCA bool
	for _, m := range reAuthority.FindAllStringSubmatch(string(out), -1) {
		switch m[1] {
		case "Software Signing":
			hasSoftwareSigning = true
		case "Apple Code Signing Certification Authority":
			hasAppleCA = true
		}
	}
	if hasSoftwareSigning && hasAppleCA {
		id.TeamID = "APPLE"
	}
	return id
}
