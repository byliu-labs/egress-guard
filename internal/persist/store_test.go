package persist

import (
	"path/filepath"
	"testing"
)

func TestRecordFirstSeen_FirstCallIsNew(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())

	firstSeen, isNew, err := recordFirstSeen(KindCron, "0 * * * * /usr/bin/true")
	if err != nil {
		t.Fatalf("recordFirstSeen: %v", err)
	}
	if !isNew {
		t.Error("first call: want isNew=true")
	}
	if firstSeen.IsZero() {
		t.Error("first call: want a non-zero FirstSeen")
	}
}

func TestRecordFirstSeen_SecondCallIsNotNew(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())

	first, isNew1, err := recordFirstSeen(KindLaunchd, "com.example.beacon")
	if err != nil {
		t.Fatalf("recordFirstSeen (1st): %v", err)
	}
	if !isNew1 {
		t.Fatalf("1st call: want isNew=true")
	}

	second, isNew2, err := recordFirstSeen(KindLaunchd, "com.example.beacon")
	if err != nil {
		t.Fatalf("recordFirstSeen (2nd): %v", err)
	}
	if isNew2 {
		t.Error("2nd call: want isNew=false")
	}
	if !second.Equal(first) {
		t.Errorf("2nd call FirstSeen = %v, want unchanged %v", second, first)
	}
}

func TestRecordFirstSeen_DifferentLabelsAreIndependent(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())

	_, isNewA, _ := recordFirstSeen(KindCron, "job-a")
	_, isNewB, _ := recordFirstSeen(KindCron, "job-b")
	if !isNewA || !isNewB {
		t.Errorf("distinct labels must each be new on first sight: isNewA=%v isNewB=%v", isNewA, isNewB)
	}
}

func TestStateFilePath_UsesXDGStateHome(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_STATE_HOME", dir)

	got, err := stateFilePath()
	if err != nil {
		t.Fatalf("stateFilePath: %v", err)
	}
	want := filepath.Join(dir, "egress-guard", "persistence-seen.json")
	if got != want {
		t.Errorf("stateFilePath = %q, want %q", got, want)
	}
}
