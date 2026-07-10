package cli

import "testing"

func TestParseStartFlags_PortDefault(t *testing.T) {
	flags := parseStartFlags(nil)
	if flags.port != defaultRedirectPort {
		t.Errorf("port = %d, want default %d", flags.port, defaultRedirectPort)
	}
	if flags.observeOnly {
		t.Error("observe should default to false")
	}
	if flags.system {
		t.Error("system should default to false")
	}
}

func TestParseStartFlags_ObserveFlagEnablesObserveOnly(t *testing.T) {
	flags := parseStartFlags([]string{"-observe"})
	if !flags.observeOnly {
		t.Error("want observeOnly=true when -observe flag passed")
	}
}

func TestParseStartFlags_PortFlagOverridesDefault(t *testing.T) {
	flags := parseStartFlags([]string{"-port", "9999"})
	if flags.port != 9999 {
		t.Errorf("port = %d, want 9999", flags.port)
	}
}

func TestParseStartFlags_SystemFlagStillParses(t *testing.T) {
	flags := parseStartFlags([]string{"-system"})
	if !flags.system {
		t.Error("want system=true when -system flag passed")
	}
}
