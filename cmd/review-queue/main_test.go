package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/reviewqueue"
	"github.com/byliu-labs/egress-guard/internal/telemetry"
)

func TestApprove_EndToEnd_RequiresEvidenceThenSucceeds(t *testing.T) {
	dir := t.TempDir()
	queuePath := filepath.Join(dir, "queue.jsonl")
	catPath := filepath.Join(dir, "baseline.toml")

	if err := seedQueue(t, queuePath); err != nil {
		t.Fatalf("seedQueue: %v", err)
	}

	err := approve([]string{
		"-queue", queuePath, "-catalog", catPath,
		"-exe", "curl", "-team", "REALDEV001", "-host", "api.example.com", "-verdict", "allow",
	})
	if err == nil {
		t.Fatal("approve: want error with no evidence set")
	}

	if err := evidence([]string{
		"-queue", queuePath,
		"-exe", "curl", "-team", "REALDEV001", "-host", "api.example.com", "-verdict", "allow",
		"-evidence", "notarized Developer ID, verified via codesign -dv",
		"-confidence", "high",
	}); err != nil {
		t.Fatalf("evidence: %v", err)
	}

	if err := approve([]string{
		"-queue", queuePath, "-catalog", catPath,
		"-exe", "curl", "-team", "REALDEV001", "-host", "api.example.com", "-verdict", "allow",
	}); err != nil {
		t.Fatalf("approve after evidence: %v", err)
	}

	b, err := os.ReadFile(catPath)
	if err != nil {
		t.Fatalf("read catalog file: %v", err)
	}
	if !strings.Contains(string(b), "api.example.com") {
		t.Fatalf("catalog file does not contain promoted host:\n%s", b)
	}
}

func TestApprove_EndToEnd_RoundTripsBundleIdentity(t *testing.T) {
	dir := t.TempDir()
	queuePath := filepath.Join(dir, "queue.jsonl")
	catPath := filepath.Join(dir, "baseline.toml")
	if err := seedOneReportWithIdentity(queuePath, "Safari", "APPLETEAM", "com.apple.Safari", true, "updates.example.com", "allow", "uuid-1"); err != nil {
		t.Fatalf("seedOneReportWithIdentity: %v", err)
	}

	baseArgs := []string{
		"-queue", queuePath,
		"-exe", "Safari",
		"-team", "APPLETEAM",
		"-bundle", "com.apple.Safari",
		"-signed",
		"-host", "updates.example.com",
		"-verdict", "allow",
	}
	evidenceArgs := append(append([]string{}, baseArgs...),
		"-evidence", "codesign identity and bundle verified",
		"-confidence", "high",
	)
	if err := evidence(evidenceArgs); err != nil {
		t.Fatalf("evidence: %v", err)
	}
	approveArgs := append(append([]string{}, baseArgs...), "-catalog", catPath)
	if err := approve(approveArgs); err != nil {
		t.Fatalf("approve: %v", err)
	}
	b, err := os.ReadFile(catPath)
	if err != nil {
		t.Fatalf("read catalog file: %v", err)
	}
	if !strings.Contains(string(b), "bundle_id = \"com.apple.Safari\"") {
		t.Fatalf("catalog file does not contain bundle identity:\n%s", b)
	}
	if !strings.Contains(string(b), "signed_required = true") {
		t.Fatalf("catalog file does not contain signed_required identity:\n%s", b)
	}
}

func seedQueue(t *testing.T, queuePath string) error {
	t.Helper()
	return seedOneReport(queuePath, "curl", "REALDEV001", "api.example.com", "allow", "uuid-1")
}

func seedOneReportWithIdentity(queuePath, exe, team, bundle string, signed bool, host, verdict, uuid string) error {
	q, err := reviewqueue.Open(queuePath)
	if err != nil {
		return err
	}
	defer q.Close()
	id := catalog.Identity{ExeBasename: exe, TeamID: team, BundleID: bundle, SignedRequired: signed}
	return q.Ingest(telemetry.NewReport(uuid, id, host, verdict))
}
