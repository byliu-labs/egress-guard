# internal/cli — the `egress-guard` command surface

<!-- L2 leaf. Delta only. Registered in docs/context-map.yaml. -->

`internal/cli` owns the user-facing commands and the install/uninstall lifecycle:
allow/deny list edits, daemon supervision and flags, launchd installation, status
probing, log tailing, telemetry opt-in, and baseline refresh.

## Interfaces

| Area | Files |
|------|-------|
| List edits | `allow.go`, `exempt.go`, writers (`alwayswriter.go`, `ratifywriter.go`) |
| Daemon | `daemon.go` (flags, supervision, baseline refresher) |
| Install lifecycle | `install.go`, `install_darwin.go`, `launchdaemon_darwin.go`, `paths.go` |
| Observability | `status_darwin.go`, `status_probe_darwin.go`, `tail.go`, `telemetry.go` |

## Contracts & gotchas (package-specific)

- **The baseline refresher keeps the last good build.** A failed rebuild must not replace
  a working baseline with an empty one — an empty baseline reclassifies every normal host
  as drift and buries the user in prompts.
- **A missing log and a missing cache mean "empty", not "error".** First run is the
  common case; treat absence as a legitimate starting state.
- **Install is idempotent and its paths are absolute.** It writes launchd plists and
  binaries as root; a relative path resolved against an unexpected working directory
  installs into the wrong place with root privileges.
- **Status probing must not prompt for privileges.** Reading state is a read; if a probe
  needs root to answer, it reports unknown rather than escalating. An unattributed root
  prompt on relaunch is a shipped bug, not an inconvenience.
- **List writers are separate on purpose.** "Always allow" (user intent) and "ratified"
  (accepted after a prompt) are different provenance; do not merge them into one writer.

## Related docs (up the tree)

- Root `CLAUDE.md` — security laws, commands, build-tagged platform pairs
