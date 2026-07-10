package cli

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
	"github.com/byliu-labs/egress-guard/internal/config"
)

// Allow appends hosts to the user allowlist.
func Allow(args []string) error { return modifyUserList(args, true) }

// Deny appends hosts to the user denylist.
func Deny(args []string) error { return modifyUserList(args, false) }

func modifyUserList(args []string, allow bool) error {
	fs := flag.NewFlagSet("allow", flag.ExitOnError)
	fs.Parse(args)
	if fs.NArg() == 0 {
		return errors.New("usage: egress-guard allow|deny <hostname> [<hostname>...]")
	}
	path, err := userAllowlistPath()
	if err != nil {
		return fmt.Errorf("resolve user allowlist path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	cur, err := config.LoadFromFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	add := fs.Args()
	if allow {
		cur.Allow = appendUnique(cur.Allow, add)
	} else {
		cur.Deny = appendUnique(cur.Deny, add)
	}

	out := config.File{
		Allow: config.Section{Hosts: cur.Allow},
		Deny:  config.Section{Hosts: cur.Deny},
	}
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if err := toml.NewEncoder(f).Encode(out); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	f.Close()
	if err := os.Rename(tmp, path); err != nil {
		return err
	}

	verb := "allow"
	if !allow {
		verb = "deny"
	}
	fmt.Printf("egress-guard: %sed %v (saved to %s)\n", verb, add, path)
	fmt.Println("Reload the daemon with `launchctl kickstart -k gui/$(id -u)/com.byliu.egress-guard` (v0.1)")
	return nil
}

func appendUnique(src, add []string) []string {
	seen := map[string]bool{}
	for _, s := range src {
		seen[s] = true
	}
	for _, a := range add {
		if !seen[a] {
			src = append(src, a)
			seen[a] = true
		}
	}
	return src
}
