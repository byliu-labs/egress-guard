package kernel

import (
	"testing"
)

func TestDefaultInstaller(t *testing.T) {
	got := Default()
	if got == nil {
		t.Fatal("Default() returned nil")
	}
	assertDefaultInstallerType(t, got)
}
