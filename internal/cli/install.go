package cli

import (
	"flag"
	"fmt"
	"os"

	"github.com/byliu-labs/egress-guard/internal/kernel"
)

const defaultRedirectPort = 8443

// getEuid is the indirection point so tests can simulate root and non-root
// invocations without actually running as either. Production code never
// reassigns it.
var getEuid = os.Geteuid

// Keep the two installers in distinct wrappers: both functions accept a port,
// so passing them positionally would otherwise compile after an accidental
// swap.
type daemonInstaller struct {
	install func(int) error
}

type kernelInstaller struct {
	install func(int) error
}

type daemonUninstaller struct {
	uninstall func() error
}

func installProtection(port int, daemon daemonInstaller, kernel kernelInstaller, uninstall daemonUninstaller, hadPrevious bool) error {
	if err := daemon.install(port); err != nil {
		return fmt.Errorf("install boot-resident daemon: %w", err)
	}
	if err := kernel.install(port); err != nil {
		if hadPrevious {
			return fmt.Errorf("install kernel rules: %w", err)
		}
		if rollbackErr := uninstall.uninstall(); rollbackErr != nil {
			return fmt.Errorf("install kernel rules: %w (daemon rollback: %v)", err, rollbackErr)
		}
		return fmt.Errorf("install kernel rules: %w", err)
	}
	return nil
}

var installProtectionFn = installProtection

// Install writes the platform kernel rules and installs the boot-resident
// System-domain LaunchDaemon. Requires root.
func Install(args []string) error {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	port := fs.Int("port", defaultRedirectPort, "daemon listen port")
	fs.Parse(args)

	if getEuid() != 0 {
		return fmt.Errorf("install requires root: re-run with sudo")
	}
	k := kernel.Default()
	if err := installProtectionFn(*port,
		daemonInstaller{install: installLaunchDaemon},
		kernelInstaller{install: k.Install},
		daemonUninstaller{uninstall: uninstallLaunchDaemon},
		BootDaemonInstalled(),
	); err != nil {
		return err
	}
	fmt.Printf("egress-guard: kernel rules installed (redirect 443 -> 127.0.0.1:%d)\n", *port)
	fmt.Println("egress-guard: boot-resident daemon installed (starts at boot, before login)")
	return nil
}

// Enable installs and loads the user-domain LaunchAgent unless the
// boot-resident LaunchDaemon is already covering enforcement.
func Enable(args []string) error {
	fs := flag.NewFlagSet("enable", flag.ExitOnError)
	port := fs.Int("port", defaultRedirectPort, "daemon listen port")
	fs.Parse(args)

	if getEuid() == 0 {
		return fmt.Errorf("enable must be run as your user, not root.\n" +
			"The user LaunchAgent must be owned by you so the daemon can write its\n" +
			"state files. Re-run without sudo:\n\n" +
			"  egress-guard enable")
	}
	if launchDaemonInstalled() {
		if err := uninstallLaunchAgent(); err != nil {
			return fmt.Errorf("remove superseded LaunchAgent: %w", err)
		}
		fmt.Println("egress-guard: boot-resident daemon already installed (`sudo egress-guard install`);")
		fmt.Println("`enable` is a no-op. Any previous per-user LaunchAgent has been removed.")
		return nil
	}
	if err := installLaunchAgent(*port); err != nil {
		return err
	}
	fmt.Println("egress-guard: LaunchAgent installed (will start automatically at login)")
	return nil
}

// Uninstall removes whichever half of the install matches the current
// privilege level. Run as root: removes pf rules and the LaunchDaemon. Run as
// user: removes any legacy LaunchAgent.
// Idempotent — running with the wrong privilege twice is harmless.
func Uninstall(args []string) error {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	fs.Parse(args)

	if getEuid() == 0 {
		k := kernel.Default()
		if err := k.Uninstall(); err != nil {
			return err
		}
		if err := uninstallLaunchDaemon(); err != nil {
			return err
		}
		fmt.Println("egress-guard: kernel rules removed")
		fmt.Println("egress-guard: boot-resident daemon removed")
		return nil
	}
	if err := uninstallLaunchAgent(); err != nil {
		return err
	}
	fmt.Println("egress-guard: LaunchAgent removed (if one was present)")
	fmt.Println("Next: run `sudo egress-guard uninstall` to remove the kernel rules and boot-resident daemon.")
	return nil
}
