package catalogbuild

import (
	"bytes"
	"testing"
	"time"

	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/exempt"
)

const baselineDir = "../../catalog/baseline"

func TestLoadBaselineDir_RealFragmentsAreValid(t *testing.T) {
	c, err := LoadBaselineDir(baselineDir)
	if err != nil {
		t.Fatalf("LoadBaselineDir(%s): %v", baselineDir, err)
	}
	for _, host := range []string{"pypi.org", "registry.npmjs.org", "github.com"} {
		if !c.HasHost(host) {
			t.Errorf("baseline is missing expected host %q", host)
		}
	}
}

func TestCompileExempt_RealFragmentsRoundTrip(t *testing.T) {
	b, err := CompileExempt("../../catalog/exempt")
	if err != nil {
		t.Fatalf("CompileExempt: %v", err)
	}
	if len(b) == 0 {
		t.Fatal("CompileExempt produced empty output")
	}
	if _, err := exempt.LoadFromString(string(b)); err != nil {
		t.Fatalf("compiled exempt catalog fails exempt.LoadFromString: %v", err)
	}
}

func TestCompileBaseline_RoundTrips(t *testing.T) {
	compileNow = func() time.Time { return time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { compileNow = func() time.Time { return time.Now().UTC() } })
	c, err := LoadBaselineDir(baselineDir)
	if err != nil {
		t.Fatalf("LoadBaselineDir: %v", err)
	}
	b, err := CompileBaseline(c)
	if err != nil {
		t.Fatalf("CompileBaseline: %v", err)
	}
	reloaded, err := catalog.Load(b)
	if err != nil {
		t.Fatalf("compiled bytes do not round-trip: %v\n---\n%s", err, b)
	}
	if !reloaded.HasHost("pypi.org") {
		t.Error("round-tripped catalog lost pypi.org")
	}
	if got := reloaded.IssuedAt(); got != "2026-08-16T12:00:00Z" {
		t.Fatalf("IssuedAt = %q", got)
	}
}

func TestCompileBaseline_ReusesIssuedAtWhenEntriesAreUnchanged(t *testing.T) {
	firstNow := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	secondNow := firstNow.Add(time.Hour)
	compileNow = func() time.Time { return firstNow }
	t.Cleanup(func() { compileNow = func() time.Time { return time.Now().UTC() } })

	c, err := LoadBaselineDir(baselineDir)
	if err != nil {
		t.Fatalf("LoadBaselineDir: %v", err)
	}
	first, err := CompileBaseline(c)
	if err != nil {
		t.Fatalf("CompileBaseline first: %v", err)
	}

	compileNow = func() time.Time { return secondNow }
	reloaded, err := catalog.Load(first)
	if err != nil {
		t.Fatalf("reload first: %v", err)
	}
	second, err := CompileBaseline(reloaded)
	if err != nil {
		t.Fatalf("CompileBaseline second: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("unchanged catalog fragments produced a byte-different artifact")
	}
}

func TestCompileBaseline_EmptyCatalogRoundTrips(t *testing.T) {
	b, err := CompileBaseline(&catalog.Catalog{})
	if err != nil {
		t.Fatalf("empty catalog should compile: %v", err)
	}
	if _, err := catalog.Load(b); err != nil {
		t.Fatalf("empty compiled catalog must still round-trip: %v", err)
	}
}

var _ = catalog.CurrentSchemaVersion
