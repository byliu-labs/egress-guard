package cli

import (
	"fmt"

	"github.com/byliu-labs/egress-guard/internal/telemetry"
)

// Telemetry manages the opt-in telemetry toggle.
func Telemetry(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: egress-guard telemetry enable|disable|status")
	}
	home, err := resolveHome()
	if err != nil {
		return fmt.Errorf("resolve home for telemetry config: %w", err)
	}
	path := telemetry.ConfigPath(home)

	switch args[0] {
	case "status":
		cfg, err := telemetry.LoadConfig(path)
		if err != nil {
			return fmt.Errorf("load telemetry config: %w", err)
		}
		fmt.Printf("telemetry: enabled=%v endpoint=%q\n", cfg.Enabled, cfg.Endpoint)
		return nil
	case "enable":
		cfg, err := telemetry.LoadConfig(path)
		if err != nil {
			return fmt.Errorf("load telemetry config: %w", err)
		}
		cfg.Enabled = true
		if cfg.Endpoint == "" {
			cfg.Endpoint = telemetry.DefaultEndpoint
		}
		if err := telemetry.EnsureInstallUUID(path, cfg); err != nil {
			return err
		}
		if err := telemetry.SaveConfig(path, cfg); err != nil {
			return err
		}
		fmt.Println("telemetry: enabled - see docs/telemetry-disclosure.md for exactly what is sent")
		return nil
	case "disable":
		cfg, err := telemetry.LoadConfig(path)
		if err != nil {
			return fmt.Errorf("load telemetry config: %w", err)
		}
		cfg.Enabled = false
		if err := telemetry.SaveConfig(path, cfg); err != nil {
			return err
		}
		fmt.Println("telemetry: disabled")
		return nil
	default:
		return fmt.Errorf("usage: egress-guard telemetry enable|disable|status (got %q)", args[0])
	}
}
