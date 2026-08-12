# internal/prompt — ask the user, within a deadline

<!-- L2 leaf. Delta only. Registered in docs/context-map.yaml. -->

`internal/prompt` is the human-in-the-loop subsystem: a `Decider` that queues unknown-host
connections, asks via a platform notifier, and returns Allow/Deny before a deadline.
It composes `catalog` facts, `drift` classification, `explain` opinions, `persist`
attribution, and `procid` identity into one question a person can answer.

## Interfaces

| Area | Files |
|------|-------|
| Decider | `New(Options) *CoreDecider` |
| Notifier | `DefaultPlatformNotifier()`, darwin osascript implementation |
| Burst control | `NewCoalescer(inner, window, burst)` |

## Contracts & gotchas (package-specific)

- **Timeout denies. Always.** The deadline exists because a blocked connection with no
  human present must not become an allow. Any new exit path from the wait needs an
  explicit deny default.
- **Coalescing groups by registrable domain within a window** — one `pip install` fans out
  to many hosts, and a prompt per connection is a denial-of-attention that trains the
  user to click Allow. Do not widen the group key past the registrable domain.
- **The AppleScript dialog is built by escaping, not by string concatenation.** Hostnames
  and process names are attacker-influenced; `escapeAS` and the direct-argv call sites
  are load-bearing security code with tests.
- **A model opinion is rendered as an opinion.** The dialog must keep the catalog's
  confidence and the explainer's guess visually distinct — never present a generated
  explanation as a verified fact.

## Related docs (up the tree)

- Root `CLAUDE.md` — default-deny law, "model opinions are labeled"
- `internal/drift/` — how "is this normal for this machine?" is computed
