//go:build darwin

package prompt

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// darwinNotifier implements Notifier using osascript display dialog.
type darwinNotifier struct{}

// DefaultPlatformNotifier returns the darwin-native notifier.
func DefaultPlatformNotifier() Notifier {
	return &darwinNotifier{}
}

// Notify displays an osascript dialog and returns the user's choice.
// If EGRESS_GUARD_OSASCRIPT_RESULT env var is set, parses and returns that
// (for testing without popping dialogs).
func (d *darwinNotifier) Notify(ctx context.Context, req Request) (Action, error) {
	// Test override: avoid real dialogs in unit tests.
	if override := os.Getenv("EGRESS_GUARD_OSASCRIPT_RESULT"); override != "" {
		return parseDarwinChoice(override), nil
	}

	body := dialogBody(req)
	script := darwinDialogScript(body)

	cmd := exec.CommandContext(ctx, "osascript", "-e", script)
	out, err := cmd.Output()
	if err != nil {
		return ActionDeny, err
	}

	choice := strings.TrimSpace(string(out))
	return parseDarwinChoice(choice), nil
}

// dialogBody returns the text to display in the dialog.
func dialogBody(req Request) string {
	if req.RegDom == "(burst)" {
		return fmt.Sprintf("%s is making many new outbound connections. Review or deny all?", req.Proc.Comm)
	}
	return RenderPrompt(req)
}

// darwinDialogScript returns the AppleScript command.
func darwinDialogScript(body string) string {
	escaped := escapeAS(body)
	return fmt.Sprintf(`display dialog "%s" buttons {"Deny", "Deny always", "Allow once", "Allow always"} default button "Deny" with title "egress-guard" with icon caution
return button returned of result`, escaped)
}

// escapeAS escapes backslashes and quotes for safe AppleScript interpolation.
// MUST escape backslashes before quotes to avoid breaking the escaping.
func escapeAS(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	return s
}

// parseDarwinChoice maps button label to Action.
func parseDarwinChoice(choice string) Action {
	switch choice {
	case "Allow once":
		return ActionAllowOnce
	case "Allow always":
		return ActionAllowAlways
	case "Deny always":
		return ActionDenyAlways
	default:
		// Default button is "Deny", timeout also returns deny.
		return ActionDeny
	}
}
