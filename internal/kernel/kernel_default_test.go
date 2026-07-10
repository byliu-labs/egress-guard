//go:build !darwin

package kernel

import "testing"

func assertDefaultInstallerType(t *testing.T, got RulesInstaller) {
	t.Helper()
	if _, ok := got.(unsupported); !ok {
		t.Errorf("expected unsupported, got %T", got)
	}
}
