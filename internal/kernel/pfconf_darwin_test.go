//go:build darwin

package kernel

import (
	"strings"
	"testing"
)

const stockPfConf = `# Default PF configuration file.
scrub-anchor "com.apple/*"
nat-anchor "com.apple/*"
rdr-anchor "com.apple/*"
dummynet-anchor "com.apple/*"
anchor "com.apple/*"
load anchor "com.apple" from "/etc/pf.anchors/com.apple"
`

func TestPfConfStateStockFileHasNeitherAnchor(t *testing.T) {
	rdr, filter := pfConfState(stockPfConf)
	if rdr || filter {
		t.Fatalf("stock pf.conf reported as wired: rdr=%v filter=%v", rdr, filter)
	}
}

func TestInsertAnchorsPutsRdrBeforeFilterAnchor(t *testing.T) {
	out, err := insertAnchors(stockPfConf)
	if err != nil {
		t.Fatal(err)
	}
	rdr := strings.Index(out, `rdr-anchor "egress-guard"`)
	filter := strings.Index(out, "\nanchor \"egress-guard\"")
	if rdr < 0 || filter < 0 || rdr > filter {
		t.Fatalf("invalid declaration order:\n%s", out)
	}
	if rdr < strings.Index(out, `rdr-anchor "com.apple/*"`) {
		t.Fatal("Apple's rdr anchor must remain first")
	}
}

func TestInsertAnchorsIsIdempotent(t *testing.T) {
	once, err := insertAnchors(stockPfConf)
	if err != nil {
		t.Fatal(err)
	}
	twice, err := insertAnchors(once)
	if err != nil {
		t.Fatal(err)
	}
	if twice != once || strings.Count(twice, `rdr-anchor "egress-guard"`) != 1 {
		t.Fatal("second insertion changed declarations")
	}
}

func TestInsertAnchorsCompletesPartialWiring(t *testing.T) {
	partial := strings.Replace(stockPfConf, `rdr-anchor "com.apple/*"`, "rdr-anchor \"com.apple/*\"\nrdr-anchor \"egress-guard\"", 1)
	out, err := insertAnchors(partial)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(out, `rdr-anchor "egress-guard"`) != 1 || !strings.Contains(out, "\nanchor \"egress-guard\"") {
		t.Fatalf("partial wiring not completed:\n%s", out)
	}
}

func TestRemoveAnchorsRestoresOriginal(t *testing.T) {
	wired, err := insertAnchors(stockPfConf)
	if err != nil {
		t.Fatal(err)
	}
	if got := removeAnchors(wired); got != stockPfConf {
		t.Fatalf("got %q, want %q", got, stockPfConf)
	}
	if got := removeAnchors(stockPfConf); got != stockPfConf {
		t.Fatal("unwired file changed")
	}
}

func TestInsertAnchorsRejectsMissingMarker(t *testing.T) {
	if _, err := insertAnchors("# no anchor points\n"); err == nil {
		t.Fatal("expected missing marker error")
	}
}
