# CLAUDE.md

Guidance for coding agents working in this repository.

## What this is

egress-guard is a macOS egress firewall for scripting and shell traffic. The kernel (pf)
redirects outbound TCP/443 to a local daemon, which reads the SNI hostname out of the TLS
ClientHello **without decrypting**, checks it against a layered allowlist, and either
splices the connection through or drops and logs it. Everyday GUI apps are exempted so
the machine stays usable. The threat it exists for is the malicious `pip install` that
exfiltrates your credentials over HTTPS to a host you have never heard of.

Framing note: the project has moved from "destination-blocking firewall" to **host-wide
egress observatory with human-ratified enforcement**. The canonical statement lives in
`byliu-labs/egress-guard-private/PHILOSOPHY.md` (maintainers only — not a file in this repo); where an older doc
in this repo disagrees on catalog direction, that one wins. Threat models, posture
reviews and dated implementation plans also live there — this repo ships the code, the
published catalog format, and the telemetry disclosure.

**Context tree.** L0 (this file) = laws + index. L1 = `docs/` (catalog format, telemetry
disclosure). L2 = `internal/<pkg>/CLAUDE.md` leaf
deltas, auto-loaded when you work in that package, each with an `AGENTS.md` symlink so
Codex reads the same file. A child never restates a parent — it links up; no level
carries volatile values (counts, dates-as-state, line numbers). Ownership map:
[`docs/context-map.yaml`](docs/context-map.yaml), read by the advisory
`check-context-map-fresh.sh` hook.

## Security laws (Never Violate)

This is a security product; these are not style preferences.

- **Never decrypt TLS.** The daemon parses the ClientHello for SNI and nothing else. No
  MITM, no CA installation, no certificate generation — ever. If a feature needs payload
  visibility, the feature is wrong.
- **Default deny on the unknown path.** A prompt that times out denies. An explainer that
  fails denies. A catalog that will not load denies. Never add a branch where an error or
  a timeout results in the connection being allowed.
- **SNI is attacker-controlled input.** A process can lie about the hostname it is
  connecting to. That is why decisions bind SNI to the resolved IP rather than trusting
  the name alone. Treat the decision path as security-critical: changes there need a
  threat-model argument, not just a passing test.
- **Never build a shell string from a hostname, process name, or any daemon input.** The
  menu bar shells out to `osascript`/admin helpers; every call passes argv directly. A
  command-substitution path here is a local privilege-escalation bug, and it has tests
  asserting the absence of one.
- **Privilege is asked for once, deliberately.** Anything that would prompt for root on
  launch, on relaunch, or on a status poll is a regression — the daemon is boot-resident
  precisely so the user is not re-prompted.
- **Telemetry is opt-in, anonymous, and minimal-field**, and what it sends is documented
  in `docs/telemetry-disclosure.md`. A field added to the payload without a matching edit
  to that doc is a disclosure violation.

## Commands

```bash
make build            # bin/egress-guard        (runs `make embed` first — always)
make bar              # bin/egress-guard-bar    (macOS menu bar)
make app              # EgressGuard.app via packaging/mac/build-app.sh
make test             # go test -race -count=1 ./...
make test-integration # tagged integration suite under tests/integration/
make install-dev      # build + cp to /usr/local/bin/egress-guard
make clean
```

`make embed` copies `configs/defaults.toml` into `internal/config/defaults_embedded.toml`.
It is a prerequisite of every other target because the binary embeds the defaults — a
`go build ./...` run by hand can compile against a stale or missing embed. Use the
Makefile.

Binaries: `cmd/egress-guard` (daemon + CLI), `cmd/egress-guard-bar` (menu bar),
`cmd/review-queue` (maintainer-side telemetry triage).

## Architecture

```
process → pf rdr anchor → daemon :8443 → tlsparse (SNI) → decision → splice | drop+log
                                              │
                          allowlist · catalog · exempt · signature · procid · persist
                                              │
                            unknown? → drift → explain → prompt (user ratifies)
```

| Layer | Packages |
|-------|----------|
| Kernel & transport | `kernel` (pf rules, DIOCNATLOOK), `daemon` (accept, decide, splice), `tlsparse` |
| Identity of the caller | `procid` (which process), `signature` (code signature), `persist` (what installed it), `exempt` |
| Identity of the destination | `allowlist`, `catalog`, `dnsbind` |
| Human in the loop | `drift` (is this normal?), `explain` (model opinion), `prompt` (ask + ratify), `reviewqueue` |
| Surfaces | `cli`, `menubar`, `tail`, `decisionlog`, `telemetry` |

macOS-only by design: `kernel` has an unsupported stub on other platforms. Linux returns
later as an OpenSnitch config-pack, not a daemon port.

## Conventions

- **Model opinions are labeled, never merged into facts.** `explain` output is presented
  as an opinion beside catalog facts, so the user can tell "the vendor says" from "a
  model guesses." Do not let an explanation upgrade a confidence level.
- **Every new decision branch gets a `decisionlog` entry.** The log is the product's
  audit trail; a branch that decides silently cannot be explained to a user afterwards.
- **Platform splits use `_darwin.go` / `_default.go` build-tagged pairs**, and the
  default stub must compile and behave sanely — CI builds both.
- **`go test -race` is the baseline.** The daemon is concurrent by nature; a test added
  without considering the race detector is not a test of this codebase.

## Docs

| Doc | Contents |
|-----|----------|
| `README.md` | what it is, who it is for, install |
| `ROADMAP.md`, `TODOS.md`, `CHANGELOG.md` | direction, backlog, history |
| `SECURITY.md` | disclosure policy |
| `docs/catalog-format.md` | known-good identity catalog schema |
| `docs/telemetry-disclosure.md` | exactly what opt-in telemetry sends |
