//go:build darwin

package signature

import (
	"os"
	"os/exec"
	"testing"
)

// TestDarwin_VerifySystemBinary asserts that /usr/bin/curl is signed by Apple.
func TestDarwin_VerifySystemBinary(t *testing.T) {
	if _, err := os.Stat("/usr/bin/curl"); err != nil {
		t.Skip("no /usr/bin/curl on this system")
	}
	id, err := defaultVerifier().Verify("/usr/bin/curl")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !id.Valid {
		t.Errorf("/usr/bin/curl not Valid: %+v", id)
	}
	if id.TeamID == "" {
		t.Errorf("/usr/bin/curl missing TeamID: %+v", id)
	}
}

// TestDarwin_AppleSystemBinaryNormalizesTeamID — /usr/libexec/trustd is
// Apple-signed but has TeamIdentifier="not set"; the verifier should normalize
// to TeamID="APPLE" via Authority chain detection so the catalog's
// team_id="APPLE" rules can match.
func TestDarwin_AppleSystemBinaryNormalizesTeamID(t *testing.T) {
	if _, err := os.Stat("/usr/libexec/trustd"); err != nil {
		t.Skip("/usr/libexec/trustd missing")
	}
	id, err := defaultVerifier().Verify("/usr/libexec/trustd")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !id.Valid {
		t.Errorf("trustd not valid")
	}
	if id.TeamID != "APPLE" {
		out, detailsErr := exec.Command("codesign", "-dvv", "--", "/usr/libexec/trustd").CombinedOutput()
		t.Logf("codesign details (err=%v): %s", detailsErr, out)
		t.Errorf("TeamID = %q, want APPLE (Apple system binary normalization)", id.TeamID)
	}
}

func TestDarwin_NormalizesNewMacOSSoftwareSigningAuthority(t *testing.T) {
	out := []byte("TeamIdentifier=not set\nAuthority=macOS Software Signing\nAuthority=Apple Code Signing Certification Authority\nAuthority=Apple Root CA\n")
	got := (&darwinVerifier{}).normalizeAppleSystemTeamID(out, SignedIdentity{Valid: true, TeamID: "not set"})
	if got.TeamID != "APPLE" {
		t.Fatalf("TeamID=%q, want APPLE for current macOS signing chain", got.TeamID)
	}
	withoutCA := []byte("TeamIdentifier=not set\nAuthority=macOS Software Signing\nAuthority=Unrelated CA\n")
	got = (&darwinVerifier{}).normalizeAppleSystemTeamID(withoutCA, SignedIdentity{Valid: true, TeamID: "not set"})
	if got.TeamID == "APPLE" {
		t.Fatal("normalized a non-Apple certificate chain")
	}
}

func TestDarwin_VerifyUnsignedBinary(t *testing.T) {
	tmp, _ := os.CreateTemp("", "unsigned-*")
	tmp.WriteString("#!/bin/sh\necho hi\n")
	tmp.Close()
	defer os.Remove(tmp.Name())
	os.Chmod(tmp.Name(), 0o755)

	id, err := defaultVerifier().Verify(tmp.Name())
	if err == nil && id.Valid {
		t.Errorf("expected unsigned binary to verify-fail, got %+v", id)
	}
}
