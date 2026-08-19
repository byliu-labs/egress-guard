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
  Its timestamps are wall-clock, not monotonic: darwin's monotonic clock stops during
  sleep, so a monotonic sample would survive an overnight sleep looking seconds fresh.
- **Flow records carry no user-active bit, on purpose.** A `flow` record is written when
  the connection closes, possibly hours after it was adjudicated, so the decision-time
  bit would be a lie about the close time. Absent is the honest answer; do not copy it
  across in `writeFlow`.
- **The in-flight set is a convenience, never a source of truth.** `inflight` exists so a
  connection that has not closed yet — and is therefore not in the log — can still be
  told how much else is egressing. It is in-memory only and must never be persisted or
  sampled into a counter: historical concurrency is *derived* from the log by
  `decisionlog.ConcurrencyIndex`, which is what lets a new dimension be computed over
  old history.
- **Live and derived concurrency do not yet measure the same interval.** `inflight`
  membership spans the whole of `handle()` — ClientHello read, prompt wait, splice —
  and the count is sampled at accept. The derived index measures
  `[decision.Timestamp, +flow.DurationMS)`, and `decision.Timestamp` is stamped *after*
  the prompt returns. For a prompted connection those differ by however long the human
  took. Harmless while nothing consumes the completed-flow score; fix it before wiring
  one, or live points and historical points will sit in different geometries.
- **Completed-flow scoring is off the admission path and currently unobserved.**
  `classifyCompletedFlow` runs inside `writeFlow`, after the splice, and only when
  `onCompletedScore` is set — which production never does. It must never move earlier:
  scoring before the splice means inventing byte counts, and scoring on the admission
  path means drift can delay a connection.
- **Splice is the only path that moves payload bytes, and it never inspects them.**

## Related docs (up the tree)

- Root `CLAUDE.md` — security laws, architecture map
- The SNI spoof threat model and the SNI/IP-binding review live in the private planning
  repo — read them before editing `decision.go` if you have access; the rule above holds
  either way.
