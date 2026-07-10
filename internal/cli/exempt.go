package cli

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

// ExemptApp dispatches `exempt-app {add,remove,list}`.
func ExemptApp(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: egress-guard exempt-app {add|remove|list} [bundle-id|exe-basename]")
	}
	switch args[0] {
	case "add":
		return exemptAdd(args[1:])
	case "remove":
		return exemptRemove(args[1:])
	case "list":
		return exemptList(args[1:])
	default:
		return fmt.Errorf("exempt-app: unknown subcommand %q", args[0])
	}
}

type exemptUserSchema struct {
	Macos []map[string]string `toml:"macos"`
	Linux []map[string]string `toml:"linux"`
}

func loadUserExempt(path string) (*exemptUserSchema, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &exemptUserSchema{}, nil
	}
	if err != nil {
		return nil, err
	}
	var f exemptUserSchema
	if _, err := toml.Decode(string(b), &f); err != nil {
		return nil, err
	}
	return &f, nil
}

func saveUserExempt(path string, f *exemptUserSchema) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "exempt-*.tmp")
	if err != nil {
		return err
	}
	enc := toml.NewEncoder(tmp)
	if err := enc.Encode(f); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	tmp.Close()
	return os.Rename(tmp.Name(), path)
}

func exemptAdd(args []string) error {
	fs := flag.NewFlagSet("exempt-app add", flag.ExitOnError)
	team := fs.String("team", "", "Team ID (darwin) or package (linux)")
	bundle := fs.String("bundle", "", "Bundle ID (darwin only)")
	exe := fs.String("exe", "", "Exe basename (linux or unsigned darwin)")
	fs.Parse(args)

	if *bundle == "" && *exe == "" {
		return errors.New("exempt-app add: need --bundle or --exe")
	}

	path, err := userExemptPath()
	if err != nil {
		return fmt.Errorf("resolve user exempt path: %w", err)
	}
	f, err := loadUserExempt(path)
	if err != nil {
		return err
	}
	rule := map[string]string{}
	if *bundle != "" {
		rule["bundle_id"] = *bundle
	}
	if *exe != "" {
		rule["exe_basename"] = *exe
	}
	if *team != "" {
		rule["team_id"] = *team
		rule["package"] = *team // linux uses `package` field name
	}
	// Heuristic: bundle ID present → macos; otherwise → linux. User can hand-edit.
	if *bundle != "" || strings.Contains(*exe, ".app/") {
		f.Macos = append(f.Macos, rule)
	} else {
		f.Linux = append(f.Linux, rule)
	}
	if err := saveUserExempt(path, f); err != nil {
		return err
	}
	fmt.Printf("egress-guard: added exempt rule to %s — restart daemon to apply\n", path)
	return nil
}

func exemptRemove(args []string) error {
	if len(args) == 0 {
		return errors.New("exempt-app remove: provide bundle-id or exe-basename")
	}
	target := args[0]
	path, err := userExemptPath()
	if err != nil {
		return fmt.Errorf("resolve user exempt path: %w", err)
	}
	f, err := loadUserExempt(path)
	if err != nil {
		return err
	}
	removed := 0
	f.Macos, removed = filterRules(f.Macos, target, removed)
	f.Linux, removed = filterRules(f.Linux, target, removed)
	if removed == 0 {
		return fmt.Errorf("exempt-app remove: no rule matching %q", target)
	}
	if err := saveUserExempt(path, f); err != nil {
		return err
	}
	fmt.Printf("egress-guard: removed %d rule(s) — restart daemon to apply\n", removed)
	return nil
}

func filterRules(rules []map[string]string, target string, removed int) ([]map[string]string, int) {
	out := rules[:0]
	for _, r := range rules {
		if r["bundle_id"] == target || r["exe_basename"] == target {
			removed++
			continue
		}
		out = append(out, r)
	}
	return out, removed
}

func exemptList(args []string) error {
	path, err := userExemptPath()
	if err != nil {
		return fmt.Errorf("resolve user exempt path: %w", err)
	}
	f, err := loadUserExempt(path)
	if err != nil {
		return err
	}
	if len(f.Macos) == 0 && len(f.Linux) == 0 {
		fmt.Println("(no user-added exempt rules)")
		return nil
	}
	for _, r := range f.Macos {
		fmt.Printf("[macos] %v\n", r)
	}
	for _, r := range f.Linux {
		fmt.Printf("[linux] %v\n", r)
	}
	return nil
}
