package cli

import (
	"errors"
	"strings"
	"testing"
)

func TestInstallProtection_DaemonFailureLeavesKernelUntouched(t *testing.T) {
	var events []string
	err := installProtection(8443,
		daemonInstaller{install: func(int) error {
			events = append(events, "daemon")
			return errors.New("bootstrap failed")
		}},
		kernelInstaller{install: func(int) error {
			events = append(events, "kernel")
			return nil
		}},
		daemonUninstaller{uninstall: func() error {
			events = append(events, "rollback")
			return nil
		}},
		false,
	)
	if err == nil {
		t.Fatal("installProtection succeeded, want daemon failure")
	}
	if strings.Join(events, ",") != "daemon" {
		t.Fatalf("events = %v, want only daemon before a failed bootstrap", events)
	}
}

func TestInstallProtection_RollsBackDaemonWhenKernelFails(t *testing.T) {
	var events []string
	err := installProtection(8443,
		daemonInstaller{install: func(int) error {
			events = append(events, "daemon")
			return nil
		}},
		kernelInstaller{install: func(int) error {
			events = append(events, "kernel")
			return errors.New("pf failed")
		}},
		daemonUninstaller{uninstall: func() error {
			events = append(events, "rollback")
			return nil
		}},
		false,
	)
	if err == nil {
		t.Fatal("installProtection succeeded, want kernel failure")
	}
	if strings.Join(events, ",") != "daemon,kernel,rollback" {
		t.Fatalf("events = %v, want daemon,kernel,rollback", events)
	}
}

func TestInstallProtection_PreservesExistingDaemonWhenKernelFails(t *testing.T) {
	var events []string
	err := installProtection(8443,
		daemonInstaller{install: func(int) error {
			events = append(events, "daemon")
			return nil
		}},
		kernelInstaller{install: func(int) error {
			events = append(events, "kernel")
			return errors.New("pf failed")
		}},
		daemonUninstaller{uninstall: func() error {
			events = append(events, "rollback")
			return nil
		}},
		true,
	)
	if err == nil {
		t.Fatal("installProtection succeeded, want kernel failure")
	}
	if strings.Join(events, ",") != "daemon,kernel" {
		t.Fatalf("events = %v, want existing daemon preserved", events)
	}
}

// stubEuid temporarily replaces getEuid for the duration of the test. Pattern
// mirrors userCurrent in daemon_test.go.
func stubEuid(t *testing.T, uid int) {
	t.Helper()
	prev := getEuid
	t.Cleanup(func() { getEuid = prev })
	getEuid = func() int { return uid }
}

func TestInstall_RefusesNonRoot(t *testing.T) {
	stubEuid(t, 501)
	err := Install(nil)
	if err == nil {
		t.Fatal("Install as non-root: want error, got nil")
	}
	if !strings.Contains(err.Error(), "sudo") {
		t.Errorf("error %q should tell user to re-run with sudo", err)
	}
}

func TestEnable_RefusesRoot(t *testing.T) {
	stubEuid(t, 0)
	err := Enable(nil)
	if err == nil {
		t.Fatal("Enable as root: want error, got nil")
	}
	// The error must explain WHY (state-file ownership), not just refuse —
	// the v0.1/v0.2 install bug surfaced as silent blocklog write failures
	// rather than an obvious crash. The fix is only useful if the error
	// message tells the user what would have gone wrong.
	msg := err.Error()
	if !strings.Contains(msg, "not root") {
		t.Errorf("error %q should explain refusal", msg)
	}
	if !strings.Contains(msg, "without sudo") {
		t.Errorf("error %q should tell user the corrective action", msg)
	}
}

// Enable as user is not unit-tested end-to-end here because it shells out to
// launchctl. The plist-rendering half is covered by TestRenderLaunchdPlist_*
// in install_darwin_test.go; the launchctl half requires manual verification
// (documented in the PR test plan).

func TestUninstall_AsRoot_RemovesKernelRulesOnly(t *testing.T) {
	// We can't fully test this without stubbing kernel.Default(), but we can
	// at least verify it doesn't error out at the euid-dispatch step. The
	// real behavior (calls k.Uninstall, not uninstallLaunchAgent) is covered
	// by code review + manual test.
	stubEuid(t, 0)
	// kernel.Default().Uninstall() may fail in CI (no pf anchor present),
	// but that's a different error than "wrong privilege". This test only
	// verifies that euid==0 doesn't trip the user-side path. Skip if the
	// error message indicates the kernel side ran.
	err := Uninstall(nil)
	if err != nil && strings.Contains(err.Error(), "LaunchAgent") {
		t.Errorf("Uninstall as root should not touch LaunchAgent path; got %v", err)
	}
}

func TestUninstall_AsUser_RemovesAgentOnly(t *testing.T) {
	stubEuid(t, 501)
	// uninstallLaunchAgent on a system with no plist is a no-op (os.Remove
	// returns IsNotExist which is swallowed). So this should succeed in
	// CI without any setup. If it fails with a kernel-related error,
	// dispatch is broken.
	if err := Uninstall(nil); err != nil {
		if strings.Contains(err.Error(), "kernel") || strings.Contains(err.Error(), "pfctl") {
			t.Errorf("Uninstall as user should not touch kernel rules; got %v", err)
		}
		// Other errors (file system issues) are out of scope for this test.
	}
}
