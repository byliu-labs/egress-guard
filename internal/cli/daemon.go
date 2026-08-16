package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"syscall"
	"time"

	"github.com/byliu-labs/egress-guard/internal/allowlist"
	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/config"
	"github.com/byliu-labs/egress-guard/internal/daemon"
	"github.com/byliu-labs/egress-guard/internal/decisionlog"
	"github.com/byliu-labs/egress-guard/internal/drift"
	"github.com/byliu-labs/egress-guard/internal/exempt"
	"github.com/byliu-labs/egress-guard/internal/explain"
	"github.com/byliu-labs/egress-guard/internal/kernel"
	"github.com/byliu-labs/egress-guard/internal/procid"
	"github.com/byliu-labs/egress-guard/internal/prompt"
	"github.com/byliu-labs/egress-guard/internal/signature"
	tel "github.com/byliu-labs/egress-guard/internal/telemetry"
)

// startFlags is the parsed public surface of `egress-guard start`.
type startFlags struct {
	port                   int
	system                 bool
	observeOnly            bool
	decisionLogMaxSegments int
}

func parseStartFlags(args []string) startFlags {
	fs := flag.NewFlagSet("start", flag.ExitOnError)
	port := fs.Int("port", defaultRedirectPort, "listen port")
	system := fs.Bool("system", false, "boot-resident mode: reassert kernel rules at startup")
	observe := fs.Bool("observe", false, "observe-only mode: log every decision but never enforce a block")
	maxSegments := fs.Int("decision-log-max-segments", 0, "maximum rotated decision-log segments to retain; 0 keeps all")
	fs.Parse(args)
	return startFlags{port: *port, system: *system, observeOnly: *observe, decisionLogMaxSegments: *maxSegments}
}

func decisionLogOptions(flags startFlags) decisionlog.Options {
	return decisionlog.Options{MaxSegments: flags.decisionLogMaxSegments}
}

// Start runs the daemon in the foreground. v0.1: no daemonization;
// the user runs it under launchd via `egress-guard install`.
func Start(args []string) error {
	flags := parseStartFlags(args)

	if flags.system {
		if getEuid() != 0 {
			return fmt.Errorf("start --system requires root: it reasserts kernel rules at boot")
		}
		if err := kernel.Default().Install(flags.port); err != nil {
			return fmt.Errorf("reassert kernel rules: %w", err)
		}
	}

	defaults, err := config.LoadDefaults()
	if err != nil {
		return fmt.Errorf("load defaults: %w", err)
	}
	allowPath, err := userAllowlistPath()
	if err != nil {
		return fmt.Errorf("resolve user allowlist path: %w", err)
	}
	userCfg, err := config.LoadFromFile(allowPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("load user config: %w", err)
	}

	a := allowlist.New(allowlist.Config{
		Defaults: allowlist.Layer{Allow: defaults.Allow, Deny: defaults.Deny},
		User:     allowlist.Layer{Allow: userCfg.Allow, Deny: userCfg.Deny},
	})

	state, err := stateDir()
	if err != nil {
		return fmt.Errorf("resolve state dir: %w", err)
	}
	logPath := filepath.Join(state, "blocked.log")
	bl, err := decisionlog.OpenWithOptions(logPath, decisionLogOptions(flags))
	if err != nil {
		return fmt.Errorf("open decision log: %w", err)
	}
	defer bl.Close()

	exemptCat, err := exempt.LoadDefault()
	if err != nil {
		return fmt.Errorf("load exempt defaults: %w", err)
	}
	exemptPath, err := userExemptPath()
	if err != nil {
		return fmt.Errorf("resolve user exempt path: %w", err)
	}
	if userExempt, err := exempt.LoadFromFile(exemptPath); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("load user exempt: %w", err)
		}
	} else {
		exemptCat.Merge(userExempt)
	}

	catalogPath, err := userCatalogPath()
	if err != nil {
		return fmt.Errorf("resolve user catalog path: %w", err)
	}
	baselinePath, err := baselineCatalogPath()
	if err != nil {
		return fmt.Errorf("resolve baseline catalog path: %w", err)
	}
	// liveCat is the layered known-good catalog the daemon consults: a
	// distributed baseline layer with the user's ratified layer stacked on top.
	// A Never (deny) in any layer wins in catalog.Lookup, so layering is
	// fail-safe. The same object is handed to the ratify writer, which adds new
	// user ratifications to it live and persists them to the user file only.
	liveCat, err := loadLayeredCatalog(baselinePath, catalogPath)
	if err != nil {
		return err
	}

	baselineCache, err := baselineCachePath()
	if err != nil {
		return fmt.Errorf("resolve baseline cache path: %w", err)
	}
	startupBaseline := loadStartupBaseline(logPath, baselineCache, liveCat, stdLogger{})

	ratifyWriter, err := newDaemonRatifyWriter(catalogPath, liveCat)
	if err != nil {
		return err
	}
	notifier := defaultNotifier()
	coalescer := prompt.NewCoalescer(notifier, 60*time.Second, 5)
	decider := prompt.New(prompt.Options{
		Notifier:     coalescer,
		Timeout:      30 * time.Second,
		AlwaysWriter: newAlwaysWriter(allowPath, a),
		RatifyWriter: ratifyWriter,
		Logger:       stdLogger{},
	})

	explainer := buildExplainer(func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, format+"\n", args...)
	})

	d, err := daemon.New(daemon.Options{
		Listen:      fmt.Sprintf("127.0.0.1:%d", flags.port),
		Kernel:      kernel.Default(),
		Allow:       a,
		Log:         bl,
		ProcID:      procid.Default(),
		Signature:   signature.NewCachingVerifier(signature.Default(), 256),
		Exempt:      exemptCat,
		Prompt:      decider,
		Catalog:     liveCat,
		Baseline:    startupBaseline,
		Explainer:   explainer,
		Logger:      stdLogger{},
		ObserveOnly: flags.observeOnly,
	})
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		cancel()
	}()

	// Keep the drift baseline fresh in a long-lived daemon: rebuild hourly and
	// on SIGHUP (operator "rebuild now"). The goroutine exits when ctx is
	// cancelled on SIGINT/SIGTERM.
	refresh := make(chan os.Signal, 1)
	signal.Notify(refresh, syscall.SIGHUP)
	go runBaselineRefresher(ctx, d, logPath, baselineCache, liveCat, baselineRefreshInterval, refresh, stdLogger{})

	fmt.Fprintf(os.Stderr, "egress-guard: daemon listening on 127.0.0.1:%d\n", flags.port)
	return d.Run(ctx)
}

// Stop is a v0.1 stub. v0.2 will add a proper status RPC via Unix socket.
func Stop(args []string) error {
	return fmt.Errorf("v0.1: use `launchctl unload ~/Library/LaunchAgents/com.byliu.egress-guard.plist` to stop the daemon")
}

// Status reports the install state across three layers: kernel rules (pf
// anchor), the user LaunchAgent, and the daemon process. Each layer can be
// in any state independently — the install split (todo #10) made
// "half-installed" a routine outcome that status needs to surface clearly.
//
// Each line is reported independently — a failure to query one layer (e.g.,
// pfctl needs sudo to read /dev/pf even just to list anchors) doesn't
// abort the others. Status' job is to surface what it can; bailing on
// the first error hides the rest of the picture.
func Status(args []string) error {
	k := kernel.Default()
	installed, err := k.IsInstalled()
	switch {
	case err != nil:
		fmt.Printf("kernel rules: unknown (%v — try `sudo egress-guard status`)\n", err)
	case installed:
		fmt.Println("kernel rules: INSTALLED")
	default:
		fmt.Println("kernel rules: NOT installed (run `sudo egress-guard install`)")
	}
	printLogFootprint(os.Stdout)
	return printPlatformStatus(os.Stdout)
}

func userAllowlistPath() (string, error) {
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "egress-guard", "allowlist.toml"), nil
	}
	home, err := resolveHome()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "egress-guard", "allowlist.toml"), nil
}

// configPath resolves <XDG_CONFIG_HOME|~/.config>/egress-guard/<filename>.
func configPath(filename string) (string, error) {
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "egress-guard", filename), nil
	}
	home, err := resolveHome()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "egress-guard", filename), nil
}

func userExemptPath() (string, error) { return configPath("exempt-apps.toml") }

func userCatalogPath() (string, error) { return configPath("catalog-user.toml") }

// baselineCatalogPath is the distributed known-good layer the maintainer
// installs (e.g. via `review-queue approve --catalog`). It sits beside the
// user's ratified catalog; the daemon merges it under the user layer at
// startup. Absent by default — a fresh install has no baseline until one is
// placed here.
func baselineCatalogPath() (string, error) { return configPath("catalog-baseline.toml") }

// baselineCachePath is the drift baseline cache — a recompute-on-stale snapshot
// of folded decision-log history. It lives in the state dir beside the decision
// log (derived machine state, not user config).
func baselineCachePath() (string, error) {
	state, err := stateDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(state, "baseline.json"), nil
}

// loadOrBuildBaseline returns the drift baseline the daemon should consult. It
// prefers the on-disk cache but rebuilds from decision-log history whenever the
// cache is missing, stale (the log holds newer traffic than the cache folded),
// or unreadable — then persists the rebuilt snapshot. It reads rotated segments
// as well as the live file, because BuildBaseline needs stable pairs across
// distinct days and rotation must not make learned traffic look novel again. A
// missing decision log yields an empty baseline (every connection novel until
// history accrues), not an error. cat is attached to the baseline by reference
// for catalog-aware classification.
func loadOrBuildBaseline(logPath, cachePath string, cat *catalog.Catalog, logger prompt.Logger) (*drift.Baseline, error) {
	entries, err := decisionlog.ReadHistory(logPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read decision log for baseline: %w", err)
	}
	if cached, cerr := drift.LoadBaseline(cachePath, cat); cerr == nil {
		if !cached.IsStale(entries) {
			return cached, nil
		}
	} else if !errors.Is(cerr, os.ErrNotExist) && logger != nil {
		logger.Errorf("baseline: discarding unreadable cache %s, rebuilding: %v", cachePath, cerr)
	}
	fresh := drift.BuildBaseline(cat, entries)
	if err := fresh.Save(cachePath); err != nil {
		return nil, fmt.Errorf("save baseline cache %s: %w", cachePath, err)
	}
	return fresh, nil
}

// buildExplainer constructs the advisory explainer from the environment. It is
// opt-in: no endpoint configured returns a nil explainer silently (the common
// case). A configured-but-invalid endpoint (e.g. non-https in API mode, or a
// missing key) is reported via warn and returns nil — the explainer is
// advisory, so a bad config must not stop the firewall from starting.
func buildExplainer(warn func(format string, args ...any)) explain.Explainer {
	ex, err := explain.FromEnv()
	if err == nil {
		return ex
	}
	if !errors.Is(err, explain.ErrNotConfigured) {
		warn("egress-guard: explainer disabled (invalid config): %v", err)
	}
	return ex // nil on any error path
}

// loadLayeredCatalog builds the daemon's live known-good catalog by stacking a
// distributed baseline layer under the user's ratified layer. A missing file at
// either path is an empty layer (not an error), so a machine with no baseline
// installed and no ratifications yet still starts with an empty catalog. A
// malformed file is a hard error: the daemon must not silently ignore a broken
// baseline the maintainer intended to enforce. Deny (Never) in any layer wins
// in catalog.Lookup, so merge order is not security-relevant.
func loadLayeredCatalog(baselinePath, userPath string) (*catalog.Catalog, error) {
	return catalog.LoadLayers(
		catalog.LayerFile{Name: "baseline", Path: baselinePath},
		catalog.LayerFile{Name: "user", Path: userPath},
	)
}

// baselineRefreshInterval is how often the daemon rebuilds its drift baseline
// from decision-log history in the background. Hourly keeps a long-lived
// boot-resident daemon's notion of "normal" current without re-reading the log
// on the hot path.
const baselineRefreshInterval = time.Hour

// baselineSetter is the swap surface the refresher needs; *daemon.Daemon
// satisfies it. An interface here so the refresher is testable without a live
// daemon.
type baselineSetter interface {
	SetBaseline(*drift.Baseline)
}

// runBaselineRefresher rebuilds the drift baseline on a ticker and whenever a
// signal arrives on refresh (wired to SIGHUP by cli.Start for on-demand
// rebuilds), swapping the result into setter. It returns when ctx is cancelled.
// A failed rebuild is logged and skipped — the daemon keeps the last good
// baseline; a bad rebuild never degrades enforcement.
func runBaselineRefresher(ctx context.Context, setter baselineSetter, logPath, cachePath string, cat *catalog.Catalog, interval time.Duration, refresh <-chan os.Signal, logger prompt.Logger) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-refresh:
		}
		b, err := loadOrBuildBaseline(logPath, cachePath, cat, logger)
		if err != nil {
			if logger != nil {
				logger.Errorf("baseline: background refresh failed: %v", err)
			}
			continue
		}
		setter.SetBaseline(b)
	}
}

// loadStartupBaseline returns the drift baseline to seed the daemon with. The
// baseline is observe-only enrichment, so a build failure (a corrupt decision-log
// line, an unwritable state volume) must NEVER stop the firewall from starting:
// on any error it logs and returns nil, and the daemon classifies unknown traffic
// as generic novel pairing until the background refresher succeeds. This mirrors
// runBaselineRefresher, which logs-and-skips the same failures — a bad baseline
// never degrades enforcement, at startup or at runtime.
func loadStartupBaseline(logPath, cachePath string, cat *catalog.Catalog, logger prompt.Logger) *drift.Baseline {
	b, err := loadOrBuildBaseline(logPath, cachePath, cat, logger)
	if err != nil {
		if logger != nil {
			logger.Errorf("baseline: starting without a drift baseline (build failed, refresher will retry): %v", err)
		}
		return nil
	}
	return b
}

// defaultNotifier returns the platform-native prompt notifier.
// Dispatches to osascript (darwin), notify-send (linux), or timeout-deny (other).
func defaultNotifier() prompt.Notifier {
	return prompt.DefaultPlatformNotifier()
}

func newDaemonRatifyWriter(catalogPath string, userCat *catalog.Catalog) (prompt.RatifyWriter, error) {
	inner := newCatalogRatifyWriter(catalogPath, userCat)
	home, err := resolveHome()
	if err != nil {
		return nil, fmt.Errorf("resolve home for telemetry config: %w", err)
	}
	cfgPath := tel.ConfigPath(home)
	cfg, err := tel.LoadConfig(cfgPath)
	if err != nil {
		return nil, fmt.Errorf("load telemetry config: %w", err)
	}
	if !cfg.Enabled {
		return inner, nil
	}
	if cfg.Endpoint == "" {
		cfg.Endpoint = tel.DefaultEndpoint
	}
	if err := tel.EnsureInstallUUID(cfgPath, cfg); err != nil {
		return nil, err
	}
	return tel.ReportingRatifyWriter{
		Inner:  inner,
		Cfg:    cfg,
		Sender: tel.HTTPSender{Endpoint: cfg.Endpoint},
	}, nil
}

// stdLogger adapts the stdlib log package to prompt.Logger so AlwaysWriter
// persistence failures (disk full, perm denied) reach the daemon log
// instead of vanishing into a `_` discard.
type stdLogger struct{}

func (stdLogger) Errorf(format string, args ...any) { log.Printf(format, args...) }

func stateDir() (string, error) {
	if x := os.Getenv("XDG_STATE_HOME"); x != "" {
		return filepath.Join(x, "egress-guard"), nil
	}
	home, err := resolveHome()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "state", "egress-guard"), nil
}

// userCurrent is the indirection point so tests can simulate the case where
// both $HOME and /etc/passwd lookup fail. Production code never reassigns it.
var userCurrent = user.Current

// resolveHome returns the calling user's home directory, preferring $HOME
// (set by login shells, sudo -H, GUI sessions) and falling back to
// /etc/passwd via os/user — which works even when launchd loads the agent
// with an empty environment. Returns a clear error naming $HOME if both
// sources fail, instead of letting callers silently produce relative paths.
func resolveHome() (string, error) {
	if h, err := os.UserHomeDir(); err == nil && h != "" {
		return h, nil
	}
	if u, err := userCurrent(); err == nil && u.HomeDir != "" {
		return u.HomeDir, nil
	}
	return "", fmt.Errorf(
		"cannot resolve user home directory: $HOME unset and os/user lookup failed; " +
			"set XDG_STATE_HOME / XDG_CONFIG_HOME or run as a user with a valid home")
}
