package cli

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/procid"
)

const maxShebangDepth = 8

// ResolveInterpreter follows a shebang chain to the binary proc_pidpath will
// report at runtime. Plain binaries resolve to themselves.
func ResolveInterpreter(path string) (string, error) {
	seen := make(map[string]bool, maxShebangDepth)
	cur := path
	for i := 0; i < maxShebangDepth; i++ {
		real, err := filepath.EvalSymlinks(cur)
		if err != nil {
			return "", fmt.Errorf("enroll: resolve %s: %w", cur, err)
		}
		if seen[real] {
			return "", fmt.Errorf("enroll: shebang cycle at %s", real)
		}
		seen[real] = true

		next, err := shebangTarget(real)
		if err != nil {
			return "", err
		}
		if next == "" {
			return real, nil
		}
		cur = next
	}
	return "", fmt.Errorf("enroll: shebang chain from %s exceeded %d hops", path, maxShebangDepth)
}

func shebangTarget(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("enroll: open %s: %w", path, err)
	}
	defer f.Close()

	line, err := bufio.NewReader(f).ReadString('\n')
	if err != nil && line == "" {
		return "", nil
	}
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "#!") {
		return "", nil
	}
	fields := strings.Fields(strings.TrimPrefix(line, "#!"))
	if len(fields) == 0 {
		return "", nil
	}
	if filepath.Base(fields[0]) == "env" && len(fields) > 1 {
		found, err := exec.LookPath(fields[1])
		if err != nil {
			return "", fmt.Errorf("enroll: %s names interpreter %q: %w", path, fields[1], err)
		}
		return found, nil
	}
	return fields[0], nil
}

// Candidate is one tool enrollment found on this machine.
type Candidate struct {
	InvokedAs string
	ExePath   string
	SHA256    string
	Hosts     []string
	Why       string
}

type lookPathFunc func(name string) (string, error)

func scanCatalogTools(cat *catalog.Catalog, look lookPathFunc) []Candidate {
	var out []Candidate
	hasher := procid.NewExeHasher()
	for _, e := range cat.Entries() {
		name := e.Identity.ExeBasename
		if name == "" || len(e.ExpectedDestinations) == 0 {
			continue
		}
		shim, err := look(name)
		if err != nil {
			continue
		}
		exe, err := ResolveInterpreter(shim)
		if err != nil {
			continue
		}
		real, sum, err := hasher.Hash(exe)
		if err != nil {
			continue
		}
		hosts := make([]string, 0, len(e.ExpectedDestinations))
		for _, d := range e.ExpectedDestinations {
			hosts = append(hosts, d.Host)
		}
		out = append(out, Candidate{InvokedAs: name, ExePath: real, SHA256: sum, Hosts: hosts, Why: e.Explanation})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].InvokedAs < out[j].InvokedAs })
	return out
}

func enrollEntry(c Candidate, host string, day string) catalog.Entry {
	return catalog.Entry{
		SchemaVersion:        catalog.CurrentSchemaVersion,
		Identity:             catalog.Identity{ExeBasename: filepath.Base(c.ExePath), ExePath: c.ExePath, ExeSHA256: c.SHA256},
		ExpectedDestinations: []catalog.Destination{{Host: host, Why: "enrolled: invoked as " + c.InvokedAs}},
		Explanation:          c.Why,
		Evidence:             fmt.Sprintf("enrolled %s: %s invokes %s", day, c.InvokedAs, c.ExePath),
		Confidence:           catalog.ConfidenceMedium,
		Layer:                "user",
	}
}

// Enroll finds known tools on this machine and pins them in one sitting.
func Enroll(args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	dryRun := fs.Bool("dry-run", false, "show what would be pinned and exit")
	assumeYes := fs.Bool("yes", false, "pin everything found without confirming")
	if err := fs.Parse(args); err != nil {
		return err
	}

	baselinePath, err := baselineCatalogPath()
	if err != nil {
		return err
	}
	catalogPath, err := userCatalogPath()
	if err != nil {
		return err
	}
	cat, err := loadLayeredCatalog(baselinePath, catalogPath)
	if err != nil {
		return err
	}
	found := scanCatalogTools(cat, exec.LookPath)
	if len(found) == 0 {
		fmt.Println("No known tools found on this machine; nothing to enroll.")
		return nil
	}

	fmt.Printf("Found %d known tools:\n\n", len(found))
	for _, c := range found {
		fmt.Printf("  %-8s %s\n           runs %s (%s)\n           may reach: %s\n\n",
			c.InvokedAs, c.Why, c.ExePath, c.SHA256[:12], strings.Join(c.Hosts, ", "))
	}
	if *dryRun {
		return nil
	}
	if !*assumeYes && !confirm("Pin all of these? [y/N] ") {
		fmt.Println("Nothing pinned.")
		return nil
	}

	w := newCatalogRatifyWriter(catalogPath, nil)
	day := time.Now().Format("2006-01-02")
	for _, c := range found {
		for _, h := range c.Hosts {
			if err := w.Ratify(enrollEntry(c, h, day)); err != nil {
				return fmt.Errorf("enroll %s: %w", c.InvokedAs, err)
			}
		}
	}
	fmt.Print(enrollPinnedMessage(len(found)))
	return nil
}

func enrollPinnedMessage(n int) string {
	return fmt.Sprintf("Pinned %d tools by executable interpreter. Restart the daemon for these pins to take effect.\n", n)
}

func confirm(prompt string) bool {
	fmt.Print(prompt)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return false
	}
	s := strings.ToLower(strings.TrimSpace(line))
	return s == "y" || s == "yes"
}
