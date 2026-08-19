# Changelog

All notable changes to egress-guard are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Concurrency as a derived behavioural dimension.** Behaviour points gained a
  ninth dimension, "how much else was egressing at that moment". It is computed
  by querying the decision log — a sorted open/close timeline answering
  point-in-time counts in O(log n) — never collected and never stored, so
  history written before the dimension existed still yields it. A connection
  does not count itself; denied connections count as instants, since a burst of
  denials alongside an allowed connection is the context that makes it
  interesting. The daemon tracks its own in-flight connections in memory for
  traffic not yet in the log; that count is never persisted. The new read-only
  `drift-inspect` command rebuilds clouds from a real log and reports what they
  carry. Baseline snapshots now use schema v5; older caches are treated as
  absent and rebuilt from the append-only log rather than reported as faults.
  Drift remains observe-only — nothing in the allow/deny path reads any of this,
  and the drift thresholds still need recalibrating for the new dimension.
- **Annotate-only joint drift scoring.** Decision and close-time flow records
  are joined into persisted, per-`(identity, host)` behavioural clouds. Complete
  flows receive a robustly scaled kNN distance and dimension attribution; the
  new `drift-calibrate` command reports score quantiles from a decision log.
  Handshake-time classifications explicitly report an unavailable score rather
  than fabricating normality before flow metadata exists. Baseline snapshots
  now use schema v3; v2 caches rebuild from the append-only log.
- **`user_active` on decision-log records.** Each decision now records whether a
  human had touched the keyboard or mouse in the preceding five minutes, so a
  3 a.m. beacon can be told apart from you working at 3 a.m. Sampled in the
  background from `ioreg` (`HIDIdleTime`) — never on the connection path — and
  omitted entirely when no usable sample exists, which never means "idle". The
  bit is observational: nothing in the allow/deny path reads it, and it is not
  part of the telemetry payload. macOS only; absent on other platforms.
- **macOS menu-bar app (`EgressGuard.app`).** One double-click installs the pf
  anchor and daemon behind a single admin prompt, shows live status and recent
  blocks, and offers one-click allow, pause/resume, start-at-login, and clean
  uninstall. Build with `make app`. Unsigned (Tier A) for now; signing hooks are
  stubbed in `packaging/mac/build-app.sh`.
- Public known-good catalog source under `catalog/`, plus `cmd/catalog-build`
  for compiling baseline fragments, refreshing the checked-in baseline artifact,
  embedding exempt fragments, and generating/signing Ed25519 catalog artifacts
  with `keygen` and `sign`.

### Changed
- **Breaking (catalog fetch):** `egress-guard catalog fetch` now requires
  `--pubkey <path>` and verifies `<url>.sig` before installing a downloaded
  baseline catalog. Unsigned remote catalog installs are refused.
- `egress-guard tail` is now event-driven (fsnotify — kqueue on darwin,
  inotify on linux) instead of polling every 250ms. New entries appear in
  the terminal immediately. As a side effect, `tail` now waits for the
  block log to exist on a fresh install (printing a one-line stderr
  notice) instead of exiting early — so you can leave it running
  pre-daemon-start without it returning silently.

### Fixed
- **Menu bar no longer prompts for root on every relaunch.** `FirstRunNeeded`
  probed a LaunchAgent label the current system-daemon architecture never
  registers, so it always reported "not installed". It now stat-s the
  LaunchDaemon plist, which works unprivileged.
- **The install escalation is now attributed.** A non-privileged dialog naming
  egress-guard appears before the macOS password prompt, which by itself says
  only "osascript". You can decline before any password box appears.
- Status is readable as a top menu item rather than a tooltip, and recent-block
  entries carry the date, the reason, and the host as a separate field.

### Removed
- Linux daemon stubs (`*_linux.go` and `*_linux_test.go` across `internal/{cli,kernel,procid,prompt,signature}`). All ~620 lines were unreachable without a Linux kernel-redirect implementation, which has been deprioritized. Linux support returns later as a config-pack on top of OpenSnitch — a companion tool that translates the egress-guard catalog into OpenSnitch rules rather than a native daemon port. Tracked at #11. The `RulesInstaller` / `Lookup` / `Verifier` / `Notifier` interfaces remain platform-agnostic; non-darwin builds get unsupported stubs that error out clearly instead of silently no-op'ing.

### Fixed
- Version constant in `cmd/egress-guard/main.go` was still `"0.1.0"` after the v0.2.0 release. Bumped to `"0.2.0"`.

### Security
- **Root command injection via the app-bundle path in the menu-bar installer
  (`internal/menubar`).** `AdminInstallScript` interpolates the bundle location
  (`os.Executable`) into a shell command that runs as root behind the admin
  prompt, so a bundle planted under a path containing shell metacharacters could
  reintroduce a root command. Closed on two layers: (1) every interpolated path
  is now POSIX single-quoted (`shellSingleQuote`), neutralizing the inner
  do-shell-script root shell; (2) the osascript invocation no longer goes through
  an intermediate `/bin/sh -c` — it is executed via direct argv (`osascript -e
  <script>`), removing the outer shell whose double-quoted context would
  otherwise expand `$(...)`/backticks before the single-quoting applied.
  Regression tests run crafted paths through a real shell and assert the
  metacharacters stay inert.

## [v0.2.0] — 2026-05-06

The "default-on for non-experts" milestone. Adds a process-identity layer,
a curated exempt-app catalog, and an interactive prompt subsystem so unknown
destinations surface to the user instead of being silently denied. Browsers,
Slack, system services and other signed GUI apps now ride through without
ever hitting the allowlist.

### Added
- Process-identity layer with platform-specific lookup:
  - darwin: socket → pid via `lsof` 4-tuple match (`local_ip:port → remote_ip:port`),
    then `proc_pidpath` for the executable
  - linux: socket → inode via `/proc/net/tcp{,6}` walk, then `/proc/<pid>/exe`
- Code-signature verification:
  - darwin: `codesign -dv` parses `TeamIdentifier` + bundle ID, with `codesign -v`
    integrity check so a tampered bundle is rejected
  - linux: package-ownership check via `dpkg -S` / `rpm -qf` (ownership-based,
    not integrity-based — documented asymmetry vs darwin)
- Bundled exempt-app catalog (`configs/exempt.toml`, embedded) covering common
  browsers, chat clients, package GUIs, and Apple/system services
- User-override exempt file at `~/.config/egress-guard/exempt.toml`
  (`exempt.LoadFromFile`) merged on top of the bundled catalog
- CLI: `egress-guard exempt-app add | remove | list` for managing user overrides
- Tri-state allowlist verdict: `Allow` / `Deny` / `Unknown` (was implicitly
  binary; `Unknown` is what now triggers the prompt path instead of a silent deny)
- Prompt subsystem (`internal/prompt`):
  - `Decider` with 30s timeout-deny default
  - Four user actions: `Deny` (default + on timeout), `Deny always`,
    `Allow once`, `Allow always`
  - `AlwaysWriter` persists `Deny always` / `Allow always` choices to the
    user allow/deny config file AND mutates the live in-memory allowlist,
    so the next connection from any process to the same registered domain
    is auto-decided without re-prompting (no daemon reload required)
  - `Coalescer` that groups concurrent requests by registered domain
    (publicsuffix-derived eTLD+1) and bounds prompt bursts
  - Platform notifiers: darwin via `osascript display dialog`, linux via
    `notify-send`, wired through a default `Notifier` interface
- Daemon decision pipeline rewired to: identity → exempt fast-path →
  SNI parse → allowlist → prompt-on-Unknown
- `daemon.Options` extended with `ProcID`, `Signature`, `Exempt`, `Prompt`
  fields (zero values preserve v0.1 behavior — see Changed)
- Block log entries extended with `PPID`, `Argv`, `Cwd`, `PName` for
  process context
- v0.2 end-to-end integration tests: exempt fast-path, prompt allow-once,
  prompt timeout-deny, burst coalescing

### Changed
- `internal/allowlist.Decide` now returns `Unknown` when no layer matches
  instead of an implicit `Deny`. Callers that previously treated the missing
  case as a deny must now choose between prompting and denying explicitly;
  the daemon does this via the prompt subsystem.
- `internal/allowlist.Allowlist` gained `AddUserAllow` / `AddUserDeny`
  methods (mutex-protected) so the prompt subsystem can mutate the live
  allowlist when the user picks `Allow always` / `Deny always`. `Decide`
  now takes an RLock; concurrent reads remain non-blocking.
- `daemon.Options` gained the four v0.2 fields above. Pre-v0.2 callers that
  leave them nil get the v0.1 behavior (no identity lookup, no exempt
  fast-path, no prompts — straight allowlist deny on miss).
- **Breaking (CLI surface):** `egress-guard install` no longer installs the
  user LaunchAgent — it now only writes the pf anchor (kernel rules). Run
  `egress-guard enable` (without sudo) as a second step to install and load
  the user agent. Previously `sudo egress-guard install` did both halves as
  root, which left the plist + state directory owned by root and caused the
  daemon to crash in a `KeepAlive` loop trying to write its blocklog. The
  split makes each half run at the right privilege level: `enable` refuses
  to run as root with a message that explains why.
- `egress-guard uninstall` is now euid-aware: as root it removes the pf
  anchor; as user it removes the LaunchAgent. Idempotent in either order.
  Previously it required root and removed both halves (with the same
  ownership problems as install).
- `egress-guard status` now reports each layer separately — kernel rules,
  LaunchAgent, daemon — so half-installed states (which are now routine
  with the install split) are obvious. Status is also resilient to per-layer
  query failures: pfctl needs sudo to read /dev/pf, so non-root status now
  prints `kernel rules: unknown (...)` and continues to the other lines
  instead of bailing.
- `egress-guard status` warns when the default route is via a TUN-mode
  proxy interface (`utun*`). When sing-box, ClashX, V2Ray, or a Tailscale
  exit-node is active, all outbound TCP routes through that tool's TUN
  before pf's `rdr` rule can fire — egress-guard's daemon stays running
  but enforces nothing. The warning surfaces this silent-bypass case
  without the user needing to read the README's known-limitations section.

### Fixed
- Daemon no longer crashes in a launchd `KeepAlive` loop when `$HOME` is empty.
  `stateDir()` and the `~/.config/egress-guard/*.toml` resolvers now fall back
  to `/etc/passwd` via `os/user` and surface a clear error if even that fails,
  instead of silently producing relative paths like `.local/state/egress-guard`
  that fail to mkdir on the read-only system volume.
- Install plist now sets `EnvironmentVariables` (`HOME`, `PATH`) so the
  launchd-spawned daemon inherits a usable env. PATH covers both Apple Silicon
  (`/opt/homebrew/bin`) and Intel/Linux (`/usr/local/bin`) Homebrew prefixes
  plus `/usr/bin:/bin:/usr/sbin:/sbin` — the latter two are required for
  `lsof` (process identity) and `pfctl` (kernel-rule status), which would
  otherwise silently fail under launchd's restricted env.

### Notes
- **Domain grouping is finer-grained than originally planned.** The
  coalescer groups requests by publicsuffix eTLD+1, so for cloud providers
  whose subdomains are PSL entries (e.g. `s3.amazonaws.com`,
  `*.r2.cloudflarestorage.com`), each tenant subdomain becomes its own
  prompt group. Burst coalescing still bounds the total number of prompts
  per unit time, so a runaway loop won't flood the user; v0.3 may revisit
  whether to coarsen grouping for known cloud-tenant patterns.
- **Scripting interpreters and shell tools are never exempt regardless of
  signature.** `python`, `node`, `ruby`, `Rscript`, `bash`, `sh`, `curl`,
  `wget`, etc. are hardcoded into the always-filtered list — a valid
  Apple-signed `/usr/bin/python3` does not get the fast-path.
- **Apple system-service exempt rules ship but won't fully activate yet.**
  The catalog includes entries for `nsurlsessiond`, `trustd` and similar
  Apple system binaries keyed on `team_id="APPLE"`, but those binaries
  report `TeamIdentifier=not set` from `codesign -dv`, so the TeamID match
  doesn't fire today. They're already-filtered system traffic which the
  user can allowlist by hostname; a follow-up will switch the matcher to
  recognize Apple system binaries via signing-authority instead of TeamID.
- **v0.1.1 (Linux platform parity for kernel rules + `SO_ORIGINAL_DST`)
  ships separately**, not bundled into v0.2. v0.2 added the Linux
  process-identity and signature paths but the Linux kernel-redirect path
  is still the v0.1 stub.
- **macOS notifier shipped as `osascript display dialog`, not
  `UNUserNotification` as originally planned.** The pivot avoids cgo and
  keeps the build pure-Go (cross-arch release binaries stay trivial), at
  the cost of `osascript`'s hard four-button cap. ROADMAP and DESIGN.md
  §6.4 are updated to describe the actual implementation.
- **The four buttons are `Deny`, `Deny always`, `Allow once`, `Allow always`**
  on both platforms — symmetric immediate-vs-persistent semantics. There
  is intentionally no `Deny once` (24h cache) action: the prior PR-#2
  attempt at one introduced a per-process scoping bug, and the symmetric
  `Deny always` covers the persistent-block use case more honestly. The
  user can rescind a `Deny always` by editing
  `~/.config/egress-guard/allowlist.toml` or by running
  `egress-guard allow <domain>`.
- **`Allow always` and `Deny always` mutate the live allowlist immediately,
  not only at next daemon restart.** `AddUserAllow` / `AddUserDeny` on the
  `*Allowlist` type are mutex-protected; the next connection sees the new
  rule without restart. The user file is written atomically (`.tmp` →
  `rename`) before the in-memory mutation so a crash mid-write doesn't
  desync the two views.
- **Burst-prompt responses do not persist.** When the coalescer fires the
  burst dialog (`"process X is making many connections"`) it does not name
  any specific registered domain. Treating a click on `Allow always` /
  `Deny always` there as consent to permanently allowlist every regdom
  hit during the next 60s of burst replays would silently mutate user
  config for hosts the user never reviewed. The coalescer downgrades
  `AllowAlways → AllowOnce` and `DenyAlways → Deny` for both the original
  burst response and replays, so the persistence layer never sees an
  Always action for burst-context responses. Users wanting persistence
  must click `Allow always` on a per-domain prompt.

### Known limitations
- **TUN-mode transparent proxies make egress-guard a no-op.** When a tool
  like sing-box, ClashX, V2Ray, or Tailscale exit-node is active in TUN
  mode, the kernel routes all outbound TCP through a `utun*` interface
  before PF's `rdr` rule can fire. The daemon stays running and the
  install command reports success, but no traffic ever reaches it.
  `egress-guard status` now detects this case from userspace and prints
  a warning when the default route is via `utun*` — but detection is
  the only mitigation; the daemon still cannot enforce.
  Recommendation: stop the TUN proxy while
  testing or using egress-guard, OR rely on the TUN proxy's own
  allowlist features. A future Network Extension implementation
  (`NEFilterDataProvider` or `NEDNSProxyProvider`) would hook before the
  routing decision and coexist with TUN proxies cleanly — this is a
  significant architectural change (System Extension packaging, Apple
  Developer Program, managed entitlement) and not committed to a version.

## [v0.1.0] — 2026-04-30

The bare-minimum egress firewall: kernel pf rules redirect outbound TCP/443 to
a local daemon that parses TLS ClientHello SNI, applies a layered allowlist,
and either splices the connection through or closes (TCP RST) — logging
JSONL block-log entries for every decision.

### Added
- darwin pf install/uninstall (`pfctl`-based anchor at `/etc/pf.anchors/egress-guard`)
- DIOCNATLOOK ioctl on `/dev/pf` to recover the original destination for redirected connections
- TLS ClientHello SNI parser (no decryption; pure stdlib `encoding/binary` + `errors`)
- Layered allowlist resolver (KnownBad > User > Defaults) with `exact` / `*.X` / `**.X` patterns
- Bundled default allowlist (LLM APIs, package registries, code hosting, cloud auth, captive-portal probes)
- JSONL append-only block log at `~/.local/state/egress-guard/blocked.log`
- launchd LaunchAgent for auto-start at user login
- CLI: `install`, `uninstall`, `start`, `stop`, `status`, `allow`, `deny`, `tail`, `version`
- darwin sudo-gated end-to-end integration test
- Cross-arch release binaries (darwin amd64 + arm64)

### Known limitations
- darwin only — Linux interface is defined but the implementation is a stub (planned for v0.1.1)
- No process identity yet — every process's traffic is filtered, including the user's browser. v0.1 users either allowlist their browser's domains by hand or accept that browsers will fail until the v0.2 exempt-app catalog lands.
- No prompt UX yet — unknown destinations are silently denied. Block log is the only feedback channel.
- When invoked via `sudo`, `os.UserHomeDir()` returns root's home; the LaunchAgent plist lands in `/var/root/Library/LaunchAgents/` rather than the calling user's. Workaround: install via `sudo -E` or run `egress-guard start` manually as the user. Fixed in v0.2 by reading `$SUDO_USER`.

[v0.2.0]: https://github.com/byliu-labs/egress-guard/releases/tag/v0.2.0
[v0.1.0]: https://github.com/byliu-labs/egress-guard/releases/tag/v0.1.0
