package exempt

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/byliu-labs/egress-guard/internal/procid"
	"github.com/byliu-labs/egress-guard/internal/signature"
)

func TestCatalog_BrowserExemptByBundleID(t *testing.T) {
	c, err := LoadDefault()
	if err != nil {
		t.Fatalf("LoadDefault: %v", err)
	}
	pi := procid.ProcInfo{Exe: "/Applications/Safari.app/Contents/MacOS/Safari", Comm: "Safari"}
	sig := signature.SignedIdentity{Valid: true, TeamID: "APPLE", BundleID: "com.apple.Safari"}
	if !c.IsExempt(pi, sig) {
		t.Errorf("Safari (signed) not exempt")
	}
}

func TestCatalog_PythonNotExemptEvenIfSigned(t *testing.T) {
	c, err := LoadDefault()
	if err != nil {
		t.Fatalf("LoadDefault: %v", err)
	}
	pi := procid.ProcInfo{Exe: "/usr/bin/python3", Comm: "python3"}
	sig := signature.SignedIdentity{Valid: true, TeamID: "APPLE"}
	if c.IsExempt(pi, sig) {
		t.Errorf("python3 must always be filtered (the Python problem)")
	}
}

func TestCatalog_UnsignedBinaryNotExempt(t *testing.T) {
	c, err := LoadDefault()
	if err != nil {
		t.Fatalf("LoadDefault: %v", err)
	}
	pi := procid.ProcInfo{Exe: "/Applications/Safari.app/Contents/MacOS/Safari", Comm: "Safari"}
	sig := signature.SignedIdentity{Valid: false} // attacker-named binary
	if c.IsExempt(pi, sig) {
		t.Errorf("unsigned binary must not match exempt list")
	}
}

func TestCatalog_LinuxSystemServiceExempt(t *testing.T) {
	c, err := LoadDefault()
	if err != nil {
		t.Fatalf("LoadDefault: %v", err)
	}
	pi := procid.ProcInfo{Exe: "/usr/lib/systemd/systemd-resolved", Comm: "systemd-resolved"}
	sig := signature.SignedIdentity{Valid: true, TeamID: "systemd"}
	if !c.IsExempt(pi, sig) {
		t.Errorf("systemd-resolved not exempt")
	}
}

func TestCatalog_LoadUserFile(t *testing.T) {
	// Test absent file returns os.ErrNotExist.
	_, err := LoadFromFile("/nonexistent/path/file.toml")
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("LoadFromFile on absent file: want os.ErrNotExist, got %v", err)
	}

	// Create a temp TOML file with a user rule.
	tmpDir := t.TempDir()
	userFile := filepath.Join(tmpDir, "user-exempt.toml")
	userTOML := `[[macos]]
bundle_id = "com.user.MyApp"
team_id = "USERTEAM"
`
	if err := os.WriteFile(userFile, []byte(userTOML), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Load the user file.
	userCatalog, err := LoadFromFile(userFile)
	if err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}

	// Merge with defaults.
	defaults, err := LoadDefault()
	if err != nil {
		t.Fatalf("LoadDefault: %v", err)
	}
	defaults.Merge(userCatalog)

	// Verify the merged catalog applies the user rule.
	pi := procid.ProcInfo{Exe: "/Applications/MyApp.app/Contents/MacOS/MyApp", Comm: "MyApp"}
	sig := signature.SignedIdentity{Valid: true, BundleID: "com.user.MyApp", TeamID: "USERTEAM"}
	if !defaults.IsExempt(pi, sig) {
		t.Errorf("user rule not applied after merge")
	}
}

// TestCatalog_RejectsEmptyRule — an empty [[macos]]/[[linux]] block (no
// identifier set) silently matches nothing in matchMac/matchLinux, which is
// the worst kind of catalog bug. Validation at parse time fails loudly.
func TestCatalog_RejectsEmptyRule(t *testing.T) {
	if _, err := LoadFromString(`[[macos]]` + "\n"); err == nil {
		t.Errorf("expected error for empty macos rule")
	}
	if _, err := LoadFromString(`[[linux]]` + "\n"); err == nil {
		t.Errorf("expected error for empty linux rule")
	}
}

// TestCatalog_AlwaysFilteredNeverExempt — even with a valid signature and a
// catalog rule that would otherwise match, every alwaysFiltered binary stays
// filtered. Locks in AC4/5 (the Python problem) against future refactors.
func TestCatalog_AlwaysFilteredNeverExempt(t *testing.T) {
	permissive, err := LoadFromString(`
[[macos]]
exe_basename = "permissive"
team_id      = "ANY"
`)
	if err != nil {
		t.Fatalf("LoadFromString: %v", err)
	}
	sig := signature.SignedIdentity{Valid: true, TeamID: "ANY"}
	for name := range alwaysFiltered {
		// Build a rule that *would* match this exact basename if exemption
		// were allowed; alwaysFiltered must defeat it.
		permissive.mac = []MacRule{{ExeBasename: name, TeamID: "ANY"}}
		pi := procid.ProcInfo{Exe: "/path/to/" + name, Comm: name}
		if permissive.IsExempt(pi, sig) {
			t.Errorf("%q passed IsExempt — alwaysFiltered defense broken", name)
		}
	}
}
