package explain_test

import (
	"testing"

	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/explain"
)

func TestNew_AlwaysModelOpinion(t *testing.T) {
	got := explain.New("looks like a CLI updater", catalog.ConfidenceMedium, "signed by known team ID", []string{"should never open a listening socket"})
	if !got.ModelOpinion {
		t.Fatal("New must always set ModelOpinion=true; a model guess must never be indistinguishable from a catalog fact")
	}
	if got.Text == "" || got.Evidence == "" {
		t.Fatal("expected Text and Evidence to round-trip unchanged")
	}
}

func TestExplanation_HasNoCatalogEntryConversion(t *testing.T) {
	var e explain.Explanation
	if _, ok := any(e).(interface{ ToCatalogEntry() catalog.Entry }); ok {
		t.Fatal("explain.Explanation must not expose a ToCatalogEntry conversion; persisting a model opinion as a catalog fact requires human ratification")
	}
}
