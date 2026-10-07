package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/byliu-labs/egress-guard/internal/decisionlog"
	"github.com/byliu-labs/egress-guard/internal/exempt"
	"github.com/byliu-labs/egress-guard/internal/persist"
	"github.com/byliu-labs/egress-guard/internal/procid"
	"github.com/byliu-labs/egress-guard/internal/signature"
)

func TestEntryFor_SetsPersistenceForKnownPID(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())

	pi := procid.ProcInfo{
		PID:  os.Getpid(),
		PPID: os.Getppid(),
		Exe:  os.Args[0],
		Comm: filepath.Base(os.Args[0]),
	}
	if _, err := persist.Attribute(pi); err != nil {
		if strings.Contains(err.Error(), "operation not permitted") {
			t.Skipf("host process inspection blocked by sandbox: %v", err)
		}
		t.Fatalf("persist.Attribute preflight: %v", err)
	}
	entry := newDaemonForBaselineTest().entryFor(decisionlog.DecisionAllow, "", "test.example.com", pi, signature.SignedIdentity{}, decisionlog.TierDefault)
	if entry.Persistence == nil {
		t.Fatal("Persistence is nil, want populated")
	}
	if entry.Persistence.Kind == "" {
		t.Error("Persistence.Kind is empty")
	}
	t.Logf("Persistence = %+v", entry.Persistence)
}

func TestEntryFor_NilPersistenceForZeroPID(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())

	entry := newDaemonForBaselineTest().entryFor(decisionlog.DecisionDeny, "some_reason", "", procid.ProcInfo{}, signature.SignedIdentity{}, "")
	if entry.Persistence != nil {
		t.Errorf("Persistence = %+v, want nil for zero-value ProcInfo", entry.Persistence)
	}
}

var persistenceAttributeCalls int

func stubPersistenceAttribute(t *testing.T, src persist.Source, err error) func() {
	t.Helper()
	prevAttribute := persistenceAttribute
	prevCache := persistenceCache
	persistenceAttributeCalls = 0
	persistenceCache = map[persistenceKey]*persist.Source{}
	persistenceAttribute = func(procid.ProcInfo) (persist.Source, error) {
		persistenceAttributeCalls++
		return src, err
	}
	return func() {
		persistenceAttribute = prevAttribute
		persistenceCache = prevCache
		persistenceAttributeCalls = 0
	}
}

func TestEntryFor_CachesPersistenceByProcessIdentity(t *testing.T) {
	restore := stubPersistenceAttribute(t, persist.Source{Kind: persist.KindSession}, nil)
	defer restore()

	pi := procid.ProcInfo{PID: 123, PPID: 1, Exe: "/usr/bin/tool", Comm: "tool"}
	d := newDaemonForBaselineTest()
	entry1 := d.entryFor(decisionlog.DecisionAllow, "", "one.example", pi, signature.SignedIdentity{}, decisionlog.TierDefault)
	entry2 := d.entryFor(decisionlog.DecisionAllow, "", "two.example", pi, signature.SignedIdentity{}, decisionlog.TierDefault)
	if entry1.Persistence == nil || entry2.Persistence == nil {
		t.Fatalf("Persistence entries = %v, %v; want cached populated source", entry1.Persistence, entry2.Persistence)
	}
	if got := persistenceAttributeCalls; got != 1 {
		t.Errorf("persist.Attribute calls = %d, want 1 for repeated process identity", got)
	}
}

func TestDecideBranch_ExemptSkipsPersistenceAttribution(t *testing.T) {
	exempted, err := exempt.LoadFromString(`
[[macos]]
exe_basename = "Safari"
team_id      = "APPLE"
`)
	if err != nil {
		t.Fatalf("LoadFromString: %v", err)
	}
	restore := stubPersistenceAttribute(t, persist.Source{Kind: persist.KindLaunchd, Label: "com.example"}, nil)
	defer restore()

	d := newDaemonForBranch(t, stubAlwaysDeny{}, exempted)
	pi := procid.ProcInfo{PID: 124, Exe: "/Applications/Safari.app/Contents/MacOS/Safari", Comm: "Safari"}
	sig := signature.SignedIdentity{Valid: true, TeamID: "APPLE"}
	_, entry := d.decideBranch("randomsite.example", nil, pi, sig)
	if entry.Persistence != nil {
		t.Errorf("exempt entry Persistence = %+v, want nil", entry.Persistence)
	}
	if got := persistenceAttributeCalls; got != 0 {
		t.Errorf("persist.Attribute calls = %d, want 0 for exempt fast path", got)
	}
}
