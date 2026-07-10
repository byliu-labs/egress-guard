// Package exempt decides whether a given (process, signature) pair should
// bypass the allowlist filter entirely. Exempt = "the daemon does not interfere
// with this process's traffic" (DESIGN.md §4.1).
//
// Matching requires BOTH a valid signature AND an identity match. Scripting
// interpreters and shell tools are NEVER exempt (the Python problem).
package exempt

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/byliu-labs/egress-guard/internal/procid"
	"github.com/byliu-labs/egress-guard/internal/signature"
)

//go:embed defaults_embedded.toml
var defaultsTOML string

// alwaysFiltered is the hardcoded list of basenames that are NEVER exempt,
// regardless of signature or config. This is the v0.2 attack-surface model.
var alwaysFiltered = map[string]bool{
	"python": true, "python2": true, "python3": true,
	"node": true, "deno": true, "bun": true,
	"ruby": true, "perl": true, "php": true, "lua": true, "rscript": true,
	"curl": true, "wget": true, "httpie": true, "http": true, "aria2c": true,
	"sh": true, "bash": true, "zsh": true, "fish": true, "dash": true,
	"pip": true, "pip3": true, "npm": true, "yarn": true, "pnpm": true,
	"gem": true, "cargo": true, "mvn": true, "gradle": true, "composer": true,
	"brew": true, "apt": true, "apt-get": true, "dnf": true, "yum": true,
	"git": true, "ssh": true, "scp": true, "sftp": true, "rsync": true,
}

// MacRule matches a darwin process.
type MacRule struct {
	BundleID    string `toml:"bundle_id,omitempty"`
	TeamID      string `toml:"team_id,omitempty"`
	ExeBasename string `toml:"exe_basename,omitempty"`
}

// LinuxRule matches a linux process.
type LinuxRule struct {
	ExeBasename string `toml:"exe_basename,omitempty"`
	Package     string `toml:"package,omitempty"`
}

type fileSchema struct {
	Macos []MacRule   `toml:"macos"`
	Linux []LinuxRule `toml:"linux"`
}

// Catalog is the loaded set of rules.
type Catalog struct {
	mac []MacRule
	lin []LinuxRule
}

// LoadDefault parses the bundled defaults.
func LoadDefault() (*Catalog, error) {
	return LoadFromString(defaultsTOML)
}

// LoadFromString parses TOML text into a Catalog. Exported so other packages
// (notably daemon tests) can build deterministic catalogs.
//
// Rejects rules with no identifier set (an empty [[macos]] or [[linux]]
// block would otherwise silently match nothing — the worst kind of
// catalog bug to debug).
func LoadFromString(s string) (*Catalog, error) {
	var f fileSchema
	if _, err := toml.Decode(s, &f); err != nil {
		return nil, fmt.Errorf("exempt: parse: %w", err)
	}
	for i, r := range f.Macos {
		if r.BundleID == "" && r.ExeBasename == "" {
			return nil, fmt.Errorf("exempt: macos rule %d has no bundle_id or exe_basename", i)
		}
	}
	for i, r := range f.Linux {
		if r.ExeBasename == "" && r.Package == "" {
			return nil, fmt.Errorf("exempt: linux rule %d has no exe_basename or package", i)
		}
	}
	return &Catalog{mac: f.Macos, lin: f.Linux}, nil
}

// LoadFromFile parses a user-supplied catalog. Returns os.ErrNotExist if absent.
func LoadFromFile(path string) (*Catalog, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, os.ErrNotExist
	}
	if err != nil {
		return nil, fmt.Errorf("exempt: read %s: %w", path, err)
	}
	return LoadFromString(string(b))
}

// Merge appends user rules on top of defaults.
//
// NOT safe for concurrent use with IsExempt. Call only during startup, before
// the daemon's accept loop hands the Catalog to per-connection goroutines.
func (c *Catalog) Merge(other *Catalog) {
	c.mac = append(c.mac, other.mac...)
	c.lin = append(c.lin, other.lin...)
}

// IsExempt is true iff the process+signature pair matches a rule AND the
// process basename is not on the always-filtered list.
func (c *Catalog) IsExempt(pi procid.ProcInfo, sig signature.SignedIdentity) bool {
	base := filepath.Base(pi.Exe)
	if base == "" || base == "." {
		base = pi.Comm
	}
	if alwaysFiltered[strings.ToLower(base)] {
		return false
	}
	if !sig.Valid {
		return false
	}
	for _, r := range c.mac {
		if matchMac(r, base, sig) {
			return true
		}
	}
	for _, r := range c.lin {
		if matchLinux(r, base, sig) {
			return true
		}
	}
	return false
}

func matchMac(r MacRule, base string, sig signature.SignedIdentity) bool {
	if r.BundleID != "" {
		if r.BundleID != sig.BundleID {
			return false
		}
		if r.TeamID != "" && r.TeamID != sig.TeamID {
			return false
		}
		return true
	}
	if r.ExeBasename != "" && r.ExeBasename == base {
		if r.TeamID != "" && r.TeamID != sig.TeamID {
			return false
		}
		return true
	}
	return false
}

func matchLinux(r LinuxRule, base string, sig signature.SignedIdentity) bool {
	if r.ExeBasename == "" || r.Package == "" {
		return false
	}
	if r.ExeBasename != base {
		return false
	}
	if r.Package != sig.TeamID {
		return false
	}
	return true
}
