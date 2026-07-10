package signature

import (
	"errors"
	"testing"
)

func TestStub_KeyByExe(t *testing.T) {
	s := NewStub()
	s.ByExe["/Applications/Safari.app/Contents/MacOS/Safari"] = SignedIdentity{
		Valid:    true,
		TeamID:   "APPLE",
		BundleID: "com.apple.Safari",
	}
	got, err := s.Verify("/Applications/Safari.app/Contents/MacOS/Safari")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !got.Valid || got.TeamID != "APPLE" {
		t.Errorf("got %+v", got)
	}
	miss, _ := s.Verify("/tmp/sketchy")
	if miss.Valid {
		t.Errorf("unsigned binary returned Valid=true")
	}
}

func TestStub_ConfiguredErr(t *testing.T) {
	s := NewStub()
	s.Err = errors.New("test verifier failure")

	id, err := s.Verify("/anything")

	if err == nil {
		t.Fatal("Verify returned nil error; want test verifier failure")
	}
	if id.Valid {
		t.Errorf("got Valid=true; want Valid=false when error configured")
	}
}
