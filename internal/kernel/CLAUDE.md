# internal/kernel — pf rules & original-destination recovery

<!-- L2 leaf. Delta only. Registered in docs/context-map.yaml. -->

`internal/kernel` installs and removes the platform rules that redirect outbound TCP/443
to the daemon's listener, and recovers the original destination of a redirected
connection. On darwin that is a pf `rdr` anchor plus the `DIOCNATLOOK` ioctl. Non-darwin
builds get an unsupported stub — the daemon is macOS-only.

## Interfaces

`RulesInstaller` (`Install` / `Remove` / original-dst lookup), obtained via `Default()`.
Implemented by pf on darwin (`pf_darwin.go`) and the stub elsewhere (`kernel_default.go`).

## Contracts & gotchas (package-specific)

- **`Install` must stay idempotent.** It runs on every daemon start and requires root;
  a second call must not append duplicate rules. Duplicate anchors are how the redirect
  survives an uninstall and strands the user's traffic.
- **Removal must be complete and safe to run when nothing is installed.** Uninstall runs
  in contexts where the state is unknown; leaving a live `rdr` rule behind after removal
  breaks all TLS on the machine with no daemon to answer it.
- **The anchor must not advertise a dead user exemption.** There is a test for exactly
  this — a rule that names an exemption which no longer exists is a hole that reads like
  a feature.
- **`DIOCNATLOOK`'s ioctl number is ABI, not a constant you may tidy.** It is asserted by
  a test because getting it wrong silently returns the wrong original destination, and
  the daemon then adjudicates a connection that is not the one in front of it.
- **Root is required here and nowhere else.** Keep privileged work inside this package so
  the privilege boundary stays auditable.

## Related docs (up the tree)

- Root `CLAUDE.md` — security laws, "privilege is asked for once"
