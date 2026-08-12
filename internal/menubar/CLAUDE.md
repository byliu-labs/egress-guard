# internal/menubar — macOS menu bar app

<!-- L2 leaf. Delta only. Registered in docs/context-map.yaml. -->

`internal/menubar` is the macOS-only status UI behind `cmd/egress-guard-bar`: status
line, pause/resume, allow-host, uninstall, and log surfacing. Non-darwin builds are a
no-op `Run()`.

## Contracts & gotchas (package-specific)

- **Every privileged action goes through argv, never a shell string.** `osascript` and
  admin helpers are invoked directly with arguments; there is no outer shell and no
  command substitution anywhere in this package, and tests assert that. A hostname typed
  by a user or supplied by a connection reaches these call sites.
- **Do not prompt for root to display status.** The daemon is boot-resident so the user
  authorizes once; a status read that escalates produces an unattributed authorization
  dialog on every relaunch. Read the system daemon log instead.
- **The status line reports what it actually observed** — including date and reason when
  the daemon is not running. "Unknown" is a legitimate status; a cheerful default is a
  lie about whether the machine is protected.
- **This package is UI, not policy.** Pause/resume and allow-host call into `cli`/`daemon`
  paths; do not reimplement a decision or a list format here.

## Related docs (up the tree)

- Root `CLAUDE.md` — shell-string law, "privilege is asked for once"
- `internal/cli/CLAUDE.md` — the list writers and install lifecycle this UI drives
