package daemon

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/procid"
	"github.com/byliu-labs/egress-guard/internal/prompt"
	"github.com/byliu-labs/egress-guard/internal/signature"
)

type fileBackedRatifyWriter struct {
	path string
	cat  *catalog.Catalog
}

func (w *fileBackedRatifyWriter) Ratify(e catalog.Entry) error {
	if err := w.cat.Add(e); err != nil {
		return err
	}
	b, err := w.cat.Marshal()
	if err != nil {
		return err
	}
	return os.WriteFile(w.path, b, 0o644)
}

type countingNotifier struct {
	calls int
	a     prompt.Action
}

func (c *countingNotifier) Notify(_ context.Context, _ prompt.Request) (prompt.Action, error) {
	c.calls++
	return c.a, nil
}

func TestRatifyLoop_AllowAlways_SecondConnectionIsSilent(t *testing.T) {
	cat := &catalog.Catalog{}
	path := filepath.Join(t.TempDir(), "catalog-user.toml")
	notifier := &countingNotifier{a: prompt.ActionAllowAlways}
	dec := prompt.New(prompt.Options{
		Notifier:     notifier,
		RatifyWriter: &fileBackedRatifyWriter{path: path, cat: cat},
	})
	d := newDaemonForBranchWithCatalog(t, dec, cat)

	pi := procid.ProcInfo{PID: 20, Exe: "/usr/bin/driftapp", Comm: "driftapp"}
	sig := signature.SignedIdentity{Valid: true, TeamID: "TEAMX"}

	outcome1, entry1 := d.decideBranch("api.driftapp-telemetry.io", nil, pi, sig)
	if outcome1 != outcomeAllow || entry1.Reason != "user_allowed" {
		t.Fatalf("first connection: outcome=%v entry=%+v, want allow/user_allowed", outcome1, entry1)
	}
	if notifier.calls != 1 {
		t.Fatalf("Notify calls after first connection = %d, want 1", notifier.calls)
	}

	outcome2, entry2 := d.decideBranch("api.driftapp-telemetry.io", nil, pi, sig)
	if outcome2 != outcomeAllow || entry2.Reason != "catalog_fact" {
		t.Fatalf("second connection: outcome=%v entry=%+v, want allow/catalog_fact", outcome2, entry2)
	}
	if notifier.calls != 1 {
		t.Errorf("Notify calls after second connection = %d, want still 1", notifier.calls)
	}

	onDisk, err := catalog.LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile(%s): %v", path, err)
	}
	if !onDisk.Lookup(catalog.Identity{ExeBasename: "driftapp", TeamID: "TEAMX"}, "api.driftapp-telemetry.io").Found {
		t.Error("ratified entry not found on disk after Ratify")
	}
}

func TestRatifyLoop_UnsignedAllowAlways_SecondConnectionIsSilent(t *testing.T) {
	cat := &catalog.Catalog{}
	path := filepath.Join(t.TempDir(), "catalog-user.toml")
	notifier := &countingNotifier{a: prompt.ActionAllowAlways}
	dec := prompt.New(prompt.Options{
		Notifier:     notifier,
		RatifyWriter: &fileBackedRatifyWriter{path: path, cat: cat},
	})
	d := newDaemonForBranchWithCatalog(t, dec, cat)

	exePath := filepath.Join(t.TempDir(), "localtool")
	if err := os.WriteFile(exePath, []byte("genuine local tool"), 0o755); err != nil {
		t.Fatalf("write executable fixture: %v", err)
	}
	pi := procid.ProcInfo{PID: 22, Exe: exePath, Comm: "localtool"}
	sig := signature.SignedIdentity{}

	outcome1, entry1 := d.decideBranch("api.localtool.example", nil, pi, sig)
	if outcome1 != outcomeAllow || entry1.Reason != "user_allowed" {
		t.Fatalf("first connection: outcome=%v entry=%+v, want allow/user_allowed", outcome1, entry1)
	}

	outcome2, entry2 := d.decideBranch("api.localtool.example", nil, pi, sig)
	if outcome2 != outcomeAllow || entry2.Reason != "catalog_fact" {
		t.Fatalf("second connection: outcome=%v entry=%+v, want allow/catalog_fact", outcome2, entry2)
	}
	if notifier.calls != 1 {
		t.Errorf("Notify calls = %d, want 1", notifier.calls)
	}
}

func TestRatifyLoop_HashlessAllowAlways_DoesNotSilentlyAuthorizeImpostor(t *testing.T) {
	cat := &catalog.Catalog{}
	path := filepath.Join(t.TempDir(), "catalog-user.toml")
	notifier := &countingNotifier{a: prompt.ActionAllowAlways}
	dec := prompt.New(prompt.Options{
		Notifier:     notifier,
		RatifyWriter: &fileBackedRatifyWriter{path: path, cat: cat},
	})
	d := newDaemonForBranchWithCatalog(t, dec, cat)

	missing := procid.ProcInfo{PID: 23, Exe: filepath.Join(t.TempDir(), "ghosttool"), Comm: "ghosttool"}
	outcome1, entry1 := d.decideBranch("api.ghosttool.example", nil, missing, signature.SignedIdentity{})
	if outcome1 != outcomeAllow || entry1.Reason != "user_allowed" {
		t.Fatalf("first connection: outcome=%v entry=%+v, want allow/user_allowed", outcome1, entry1)
	}
	if notifier.calls != 1 {
		t.Fatalf("Notify calls after first connection = %d, want 1", notifier.calls)
	}

	impostorPath := filepath.Join(t.TempDir(), "ghosttool")
	if err := os.WriteFile(impostorPath, []byte("different binary"), 0o755); err != nil {
		t.Fatalf("write impostor: %v", err)
	}
	impostor := procid.ProcInfo{PID: 24, Exe: impostorPath, Comm: "ghosttool"}
	outcome2, entry2 := d.decideBranch("api.ghosttool.example", nil, impostor, signature.SignedIdentity{})
	if outcome2 != outcomeAllow || entry2.Reason != "user_allowed" {
		t.Fatalf("impostor connection: outcome=%v entry=%+v, want prompt allow/user_allowed", outcome2, entry2)
	}
	if notifier.calls != 2 {
		t.Fatalf("hashless ratification silently authorized impostor: Notify calls = %d, want 2", notifier.calls)
	}
}

func TestRatifyLoop_DenyAlways_SecondConnectionIsDenied(t *testing.T) {
	cat := &catalog.Catalog{}
	path := filepath.Join(t.TempDir(), "catalog-user.toml")
	notifier := &countingNotifier{a: prompt.ActionDenyAlways}
	dec := prompt.New(prompt.Options{
		Notifier:     notifier,
		RatifyWriter: &fileBackedRatifyWriter{path: path, cat: cat},
	})
	d := newDaemonForBranchWithCatalog(t, dec, cat)

	pi := procid.ProcInfo{PID: 21, Exe: "/usr/bin/badapp", Comm: "badapp"}
	sig := signature.SignedIdentity{Valid: true, TeamID: "TEAMY"}

	outcome1, entry1 := d.decideBranch("cdn.bad.example", nil, pi, sig)
	if outcome1 != outcomeDeny || entry1.Reason != "user_denied_or_timeout" {
		t.Fatalf("first connection: outcome=%v entry=%+v, want deny/user_denied_or_timeout", outcome1, entry1)
	}

	outcome2, entry2 := d.decideBranch("cdn.bad.example", nil, pi, sig)
	if outcome2 != outcomeDeny || entry2.Reason != "catalog_never_hit" {
		t.Fatalf("second connection: outcome=%v entry=%+v, want deny/catalog_never_hit", outcome2, entry2)
	}
	if notifier.calls != 1 {
		t.Errorf("Notify calls = %d, want 1", notifier.calls)
	}
}
