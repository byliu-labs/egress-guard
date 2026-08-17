# internal/daemon — the SNI-filtering proxy

<!-- L2 leaf. Delta only: the security laws (never decrypt, default deny, SNI is
     attacker-controlled) live in the root CLAUDE.md. No volatile values. Registered in
     docs/context-map.yaml. -->

`internal/daemon` accepts kernel-redirected connections, recovers their original
destination, adjudicates allow/deny/observe, and splices or closes. It is the one place
where all the identity signals meet.

It does NOT install kernel rules (`kernel`), parse TLS bytes (`tlsparse`), or decide what
a hostname *means* (`catalog`, `allowlist`).

## Interfaces

| Area | Files |
|------|-------|
| Lifecycle, options, baseline swap | `daemon.go` |
| The decision tree | `decision.go` |
| Byte plumbing | `splice.go` |

Constructed with `New(Options)` — the kernel installer, allowlist, and decision log are
injected, which is what makes the decision branches testable without root.

## Contracts & gotchas (package-specific)

- **Catalog outcomes are not one boolean.** *Found* means the prompt should show the
  catalog explanation. *Authoritative* means an expected destination can allow without
  prompting. A `never` hit denies. A basename-only baseline/pro entry is Found but not
  Authoritative; a user-ratified unsigned entry is Authoritative only when the
  executable hash was captured.
- **Baseline swaps are concurrent with classification.** The drift baseline is refreshed
  under the daemon's lock while connections are being classified; a nil baseline must
  degrade to generic classification, not panic and not allow.
- **Every branch writes a decision-log entry before returning.** A connection that is
  decided but not logged cannot be explained or ratified afterwards — the audit trail is
  the product.
- **The user-active bit is observational.** `Entry.UserActive` is stamped by the
  `entryFor*` constructor chain and is read by nothing in the decision path. A nil value
  means no usable sample, never "idle". Future code that branches on it is a bug.
- **The idle probe is never awaited.** `idle.Cached.Active()` returns the last background
  sample. Making it synchronous would put a process exec on the TLS handshake path.
- **Splice is the only path that moves payload bytes, and it never inspects them.**

## Related docs (up the tree)

- Root `CLAUDE.md` — security laws, architecture map
- The SNI spoof threat model and the SNI/IP-binding review live in the private planning
  repo — read them before editing `decision.go` if you have access; the rule above holds
  either way.
