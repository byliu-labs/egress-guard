//go:build darwin

package kernel

import "testing"

func assertDefaultInstallerType(t *testing.T, got RulesInstaller) {
	t.Helper()
	if _, ok := got.(*pfDarwin); !ok {
		t.Errorf("expected *pfDarwin, got %T", got)
	}
}
