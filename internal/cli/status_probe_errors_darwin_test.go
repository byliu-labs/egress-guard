//go:build darwin

package cli

import (
	"strings"
	"testing"
)

func TestCheckDaemonJob_Disabled113UsesDisabledRegistry(t *testing.T) {
	origDaemon := launchctlPrintDaemon
	origDisabled := launchctlPrintDisabled
	t.Cleanup(func() {
		launchctlPrintDaemon = origDaemon
		launchctlPrintDisabled = origDisabled
	})
	launchctlPrintDaemon = func() (string, error) { return "service unavailable", launchctlExitError(t, 113) }
	launchctlPrintDisabled = func() (string, error) {
		return `{"` + launchDaemonLabel + `" => true}`, nil
	}

	got := checkDaemonJob()
	if !got.Disabled || got.Unknown || got.Loaded {
		t.Fatalf("checkDaemonJob = %+v, want disabled only", got)
	}
}

func TestCheckDaemonJob_UnexpectedFailureIsUnknown(t *testing.T) {
	origDaemon := launchctlPrintDaemon
	origDisabled := launchctlPrintDisabled
	t.Cleanup(func() {
		launchctlPrintDaemon = origDaemon
		launchctlPrintDisabled = origDisabled
	})
	launchctlPrintDaemon = func() (string, error) { return "permission denied", launchctlExitError(t, 1) }
	launchctlPrintDisabled = func() (string, error) { return "", nil }

	got := checkDaemonJob()
	if !got.Unknown || got.Disabled || got.Loaded {
		t.Fatalf("checkDaemonJob = %+v, want unknown only", got)
	}
}

func TestPrintPlatformStatus_DisabledNamesEnableRemedy(t *testing.T) {
	stubLaunchctl(t, "", false)
	stubLaunchctlDaemon(t, "", false)
	launchctlPrintDaemon = func() (string, error) { return "", launchctlExitError(t, 113) }
	launchctlPrintDisabled = func() (string, error) {
		return `{"` + launchDaemonLabel + `" => true}`, nil
	}

	var out strings.Builder
	if err := printPlatformStatus(&out); err != nil {
		t.Fatalf("printPlatformStatus: %v", err)
	}
	if !strings.Contains(out.String(), "launchctl enable system/"+launchDaemonLabel) {
		t.Fatalf("status = %q, want launchctl enable remedy", out.String())
	}
	if strings.Contains(out.String(), "sudo egress-guard install") {
		t.Fatalf("status = %q, disabled jobs need enable, not reinstall", out.String())
	}
}
