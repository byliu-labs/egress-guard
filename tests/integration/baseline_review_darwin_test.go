//go:build darwin && integration

package integration

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/byliu-labs/egress-guard/internal/decisionlog"
)

func TestBaselineReviewCLIRejectRestoreWithWarmCache(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	binary := filepath.Join(dir, "egress-guard")
	build := exec.Command("go", "build", "-o", binary, "./cmd/egress-guard")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v: %s", err, out)
	}
	state := filepath.Join(dir, "state")
	config := filepath.Join(dir, "config")
	logPath := filepath.Join(state, "egress-guard", "blocked.log")
	if err := os.MkdirAll(filepath.Dir(logPath), 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	enc := json.NewEncoder(f)
	for i := 3; i >= 1; i-- {
		id := string(rune('a' + i))
		decision := decisionlog.Entry{Kind: decisionlog.KindDecision, ConnID: id, Timestamp: time.Now().Add(-time.Duration(i) * 24 * time.Hour).UTC().Format(time.RFC3339), Decision: decisionlog.DecisionAllow, Exe: "/bin/curl", Host: "evil.example"}
		flow := decisionlog.Entry{Kind: decisionlog.KindFlow, ConnID: id, BytesUp: 1, BytesDown: 1, DurationMS: 1}
		if err := enc.Encode(decision); err != nil {
			t.Fatal(err)
		}
		if err := enc.Encode(flow); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) string {
		t.Helper()
		cmd := exec.Command(binary, append([]string{"review"}, args...)...)
		cmd.Env = append(os.Environ(), "XDG_STATE_HOME="+state, "XDG_CONFIG_HOME="+config)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("review %v: %v: %s", args, err, out)
		}
		return string(out)
	}
	if out := run("--baseline"); !strings.Contains(out, "evil.example") {
		t.Fatalf("before reject: %s", out)
	}
	if out := run(); !strings.Contains(out, "recently learned baseline pairs") {
		t.Fatalf("default review omitted baseline section: %s", out)
	}
	calibrate := filepath.Join(dir, "drift-calibrate")
	calibrateBuild := exec.Command("go", "build", "-o", calibrate, "./cmd/drift-calibrate")
	calibrateBuild.Dir = root
	if out, err := calibrateBuild.CombinedOutput(); err != nil {
		t.Fatalf("build calibrate: %v: %s", err, out)
	}
	calibration := func() string {
		t.Helper()
		cmd := exec.Command(calibrate, "-log", logPath, "-train", "0.67")
		cmd.Env = append(os.Environ(), "XDG_CONFIG_HOME="+config)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("calibrate: %v: %s", err, out)
		}
		return string(out)
	}
	if out := calibration(); !strings.Contains(out, "connections scored: 1 (+0 with no history") {
		t.Fatalf("before rejection calibration: %s", out)
	}
	inspect := filepath.Join(dir, "drift-inspect")
	inspectBuild := exec.Command("go", "build", "-o", inspect, "./cmd/drift-inspect")
	inspectBuild.Dir = root
	if out, err := inspectBuild.CombinedOutput(); err != nil {
		t.Fatalf("build inspect: %v: %s", err, out)
	}
	if out, err := exec.Command(inspect, "-log", logPath).CombinedOutput(); err != nil || !strings.Contains(string(out), "rejections:              not applied") {
		t.Fatalf("inspect header: %v: %s", err, out)
	}
	run("--baseline", "--reject", "1", "--why", "unknown")
	if out := calibration(); !strings.Contains(out, "connections scored: 0 (+1 with no history") {
		t.Fatalf("calibration ignored rejection: %s", out)
	}
	if out := run("--baseline"); strings.Contains(out, "evil.example") {
		t.Fatalf("warm cache relearned rejected pair: %s", out)
	}
	if out := run("--rejected"); !strings.Contains(out, "evil.example") {
		t.Fatalf("rejected list: %s", out)
	}
	run("--restore", "1")
	if out := run("--baseline"); !strings.Contains(out, "evil.example") {
		t.Fatalf("restored pair absent: %s", out)
	}
}
