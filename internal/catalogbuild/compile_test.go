package catalogbuild

import (
	"testing"

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
