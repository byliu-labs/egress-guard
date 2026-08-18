//go:build darwin

package idle

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const probeTimeout = 15 * time.Second

// NewSystemProbe reads HIDIdleTime with a fixed, input-free argv.
func NewSystemProbe() Probe { return ioregProbe{} }

type ioregProbe struct{}

func (ioregProbe) SecondsSinceInput() (float64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ioreg", "-c", "IOHIDSystem", "-d", "4", "-r")
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	// Output waits for the stdout pipe to close, not just for the process. A
	// child that inherits the pipe and outlives the context would block the
	// refresh goroutine forever, leaving Cached.inFlight set and permanently
	// stopping every future probe. WaitDelay bounds that teardown.
	cmd.WaitDelay = 2 * time.Second
	out, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("idle: ioreg: %w", err)
	}
	return parseHIDIdleTime(string(out))
}

func parseHIDIdleTime(out string) (float64, error) {
	for _, line := range strings.Split(out, "\n") {
		_, rest, found := strings.Cut(line, "\"HIDIdleTime\"")
		if !found {
			continue
		}
		_, value, found := strings.Cut(rest, "=")
		if !found {
			continue
		}
		nanoseconds, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("idle: parse HIDIdleTime %q: %w", strings.TrimSpace(value), err)
		}
		if nanoseconds < 0 {
			return 0, fmt.Errorf("idle: negative HIDIdleTime %d", nanoseconds)
		}
		return float64(nanoseconds) / 1e9, nil
	}
	return 0, errors.New("idle: no HIDIdleTime in ioreg output")
}
