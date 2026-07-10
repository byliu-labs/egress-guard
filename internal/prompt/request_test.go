package prompt

import (
	"context"
	"testing"

	"github.com/byliu-labs/egress-guard/internal/procid"
)

func TestRequest_ZeroValueContextFieldsAreSafe(t *testing.T) {
	d := New(Options{Notifier: &StaticNotifier{A: ActionAllowOnce}})
	req := Request{
		Proc:   procid.ProcInfo{PID: 1},
		Host:   "foo.com",
		RegDom: "foo.com",
	}
	if got := d.Decide(context.Background(), req); got != Allow {
		t.Errorf("Decide() = %v, want Allow", got)
	}
	if req.CatalogMatch.Found {
		t.Error("zero-value CatalogMatch.Found should be false")
	}
	if req.CatalogMatch.Entry.Explanation != "" {
		t.Error("zero-value CatalogMatch.Entry should have empty Explanation")
	}
	if req.Drift.Class != "" {
		t.Errorf("zero-value Drift.Class = %q, want empty", req.Drift.Class)
	}
	if req.Opinion != nil {
		t.Error("zero-value Opinion should be nil")
	}
	if req.Persistence != nil {
		t.Error("zero-value Persistence should be nil")
	}
}
