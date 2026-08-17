package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/byliu-labs/egress-guard/internal/catalog"
)

func TestResolveInterpreter_FollowsShebang(t *testing.T) {
	dir := t.TempDir()
	interp := filepath.Join(dir, "myinterp")
	if err := os.WriteFile(interp, []byte("fake interpreter"), 0o755); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(dir, "tool")
	if err := os.WriteFile(script, []byte("#!"+interp+"\nprint('hi')\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	got, err := ResolveInterpreter(script)
	if err != nil {
		t.Fatalf("ResolveInterpreter: %v", err)
	}
	want, err := filepath.EvalSymlinks(interp)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestResolveInterpreter_PlainBinaryResolvesToItself(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "tool")
	if err := os.WriteFile(bin, []byte{0x7f, 'E', 'L', 'F', 0, 0, 0, 0}, 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := ResolveInterpreter(bin)
	if err != nil {
		t.Fatal(err)
	}
	want, err := filepath.EvalSymlinks(bin)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestResolveInterpreter_StopsOnShebangCycle(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a")
	b := filepath.Join(dir, "b")
	if err := os.WriteFile(a, []byte("#!"+b+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte("#!"+a+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveInterpreter(a); err == nil {
		t.Fatal("expected an error on a shebang cycle, not a hang")
	}
}

func TestScanCatalogTools_PinsResolvedInterpreter(t *testing.T) {
	dir := t.TempDir()
	interp := filepath.Join(dir, "node")
	if err := os.WriteFile(interp, []byte("node binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	shim := filepath.Join(dir, "npm")
	if err := os.WriteFile(shim, []byte("#!"+interp+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	cat := &catalog.Catalog{}
	if err := cat.Add(catalog.Entry{
		SchemaVersion:        catalog.CurrentSchemaVersion,
		Identity:             catalog.Identity{ExeBasename: "npm"},
		ExpectedDestinations: []catalog.Destination{{Host: "registry.npmjs.org", Why: "registry"}},
		Explanation:          "npm downloads packages",
		Evidence:             "fixture",
		Confidence:           catalog.ConfidenceMedium,
		Layer:                "baseline",
	}); err != nil {
		t.Fatal(err)
	}

	found := scanCatalogTools(cat, func(name string) (string, error) {
		if name == "npm" {
			return shim, nil
		}
		return "", exec.ErrNotFound
	})

	if len(found) != 1 {
		t.Fatalf("found %d candidates, want 1", len(found))
	}
	want, err := filepath.EvalSymlinks(interp)
	if err != nil {
		t.Fatal(err)
	}
	if found[0].ExePath != want {
		t.Errorf("ExePath = %q, want the interpreter %q", found[0].ExePath, want)
	}
	if found[0].InvokedAs != "npm" {
		t.Errorf("InvokedAs = %q, want npm", found[0].InvokedAs)
	}
	if len(found[0].Hosts) != 1 || found[0].Hosts[0] != "registry.npmjs.org" {
		t.Errorf("Hosts = %v, want the catalog's destinations", found[0].Hosts)
	}
}

func TestEnrollPinnedMessageSaysDaemonReloadRequired(t *testing.T) {
	msg := enrollPinnedMessage(2)
	lower := strings.ToLower(msg)
	if !strings.Contains(lower, "restart") {
		t.Fatalf("message = %q, want explicit restart requirement", msg)
	}
	if strings.Contains(lower, "will no longer prompt") {
		t.Fatalf("message = %q, must not claim a running daemon sees new pins immediately", msg)
	}
	if !strings.Contains(lower, "interpreter") {
		t.Fatalf("message = %q, want interpreter-granularity warning", msg)
	}
}
