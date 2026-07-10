package cli

import (
	"errors"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveHome_PrefersHomeEnv(t *testing.T) {
	t.Setenv("HOME", "/tmp/test-home")
	got, err := resolveHome()
	if err != nil {
		t.Fatalf("resolveHome: %v", err)
	}
	if got != "/tmp/test-home" {
		t.Errorf("resolveHome = %q, want /tmp/test-home", got)
	}
}

func TestResolveHome_FallsBackToOSUser(t *testing.T) {
	t.Setenv("HOME", "")
	prev := userCurrent
	t.Cleanup(func() { userCurrent = prev })
	userCurrent = func() (*user.User, error) {
		return &user.User{HomeDir: "/tmp/passwd-home"}, nil
	}
	got, err := resolveHome()
	if err != nil {
		t.Fatalf("resolveHome: %v", err)
	}
	if got != "/tmp/passwd-home" {
		t.Errorf("resolveHome = %q, want /tmp/passwd-home", got)
	}
}

func TestResolveHome_FailsLoudWhenBothFail(t *testing.T) {
	t.Setenv("HOME", "")
	prev := userCurrent
	t.Cleanup(func() { userCurrent = prev })
	userCurrent = func() (*user.User, error) {
		return nil, errors.New("simulated /etc/passwd failure")
	}
	_, err := resolveHome()
	if err == nil {
		t.Fatal("resolveHome: want error, got nil")
	}
	if !strings.Contains(err.Error(), "$HOME") {
		t.Errorf("error message %q does not mention $HOME (debugging aid required)", err)
	}
}

func TestStateDir_PrefersXDG(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", "/tmp/xdg-state")
	t.Setenv("HOME", "/tmp/should-be-ignored")
	got, err := stateDir()
	if err != nil {
		t.Fatalf("stateDir: %v", err)
	}
	want := filepath.Join("/tmp/xdg-state", "egress-guard")
	if got != want {
		t.Errorf("stateDir = %q, want %q", got, want)
	}
}

func TestStateDir_NeverReturnsRelativePath(t *testing.T) {
	// The bug: when $HOME and XDG_STATE_HOME are both empty AND os/user
	// fails, the old code silently returned ".local/state/egress-guard".
	// The new code must error out instead.
	t.Setenv("XDG_STATE_HOME", "")
	t.Setenv("HOME", "")
	prev := userCurrent
	t.Cleanup(func() { userCurrent = prev })
	userCurrent = func() (*user.User, error) {
		return nil, errors.New("simulated failure")
	}
	got, err := stateDir()
	if err == nil {
		t.Fatalf("stateDir = %q, want error (relative path is the bug)", got)
	}
	if got != "" {
		t.Errorf("stateDir returned non-empty path %q on error; expected empty", got)
	}
}

func TestUserAllowlistPath_UsesResolvedHome(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", "/tmp/test-home")
	got, err := userAllowlistPath()
	if err != nil {
		t.Fatalf("userAllowlistPath: %v", err)
	}
	want := filepath.Join("/tmp/test-home", ".config", "egress-guard", "allowlist.toml")
	if got != want {
		t.Errorf("userAllowlistPath = %q, want %q", got, want)
	}
}

func TestUserExemptPath_UsesResolvedHome(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", "/tmp/test-home")
	got, err := userExemptPath()
	if err != nil {
		t.Fatalf("userExemptPath: %v", err)
	}
	want := filepath.Join("/tmp/test-home", ".config", "egress-guard", "exempt-apps.toml")
	if got != want {
		t.Errorf("userExemptPath = %q, want %q", got, want)
	}
}

func TestStart_SystemFlagRequiresRoot(t *testing.T) {
	stubEuid(t, 501)
	err := Start([]string{"--system"})
	if err == nil {
		t.Fatal("Start --system as non-root: want error, got nil")
	}
	if !strings.Contains(err.Error(), "root") {
		t.Errorf("error %q should mention the root requirement", err)
	}
}
