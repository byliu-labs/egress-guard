//go:build darwin

package idle

import "testing"

const ioregSample = `
  +-o IOHIDSystem  <class IOHIDSystem, id 0x100000285, registered, matched>
      {
        "HIDIdleTime" = 43000000000
        "HIDPointerAcceleration" = 3145728
      }
`

func TestParseHIDIdleTime_ReadsNanoseconds(t *testing.T) {
	got, err := parseHIDIdleTime(ioregSample)
	if err != nil {
		t.Fatal(err)
	}
	if got != 43 {
		t.Errorf("SecondsSinceInput = %v, want 43", got)
	}
}

func TestParseHIDIdleTime_MissingPropertyIsAnError(t *testing.T) {
	if _, err := parseHIDIdleTime("no such property here"); err == nil {
		t.Fatal("missing HIDIdleTime must be an error")
	}
}

func TestParseHIDIdleTime_GarbageIsAnError(t *testing.T) {
	if _, err := parseHIDIdleTime(`"HIDIdleTime" = not-a-number`); err == nil {
		t.Fatal("unparseable HIDIdleTime must be an error")
	}
}

func TestSystemProbe_ReturnsAPlausibleValue(t *testing.T) {
	seconds, err := NewSystemProbe().SecondsSinceInput()
	if err != nil {
		t.Skipf("ioreg unavailable in this environment: %v", err)
	}
	if seconds < 0 || seconds > 86400 {
		t.Errorf("SecondsSinceInput = %v, want plausible idle time", seconds)
	}
}
