# Roadmap

A high-level view of where egress-guard is headed. The
authoritative phasing lives in [DESIGN.md §13](DESIGN.md#13-phased-rollout);
the deferred backlog lives in [TODOS.md](TODOS.md). This file is the
one-page summary.

## Released

- **v0.2.0** (2026-05-01) — default-on for non-experts: process-identity
  layer (darwin via `lsof`, linux via `/proc/net/tcp`), code-signature
  verification (darwin `codesign`, linux `dpkg`/`rpm` ownership), bundled
  exempt-app catalog with user override, `exempt-app` CLI, prompt UX with
  publicsuffix domain grouping, 30s timeout-deny, burst coalescing, and
  platform notifications (`osascript` / `notify-send`). See
  [CHANGELOG.md](CHANGELOG.md).
- **v0.1.0** (2026-04-30) — darwin foundation: kernel pf rules, SNI filter,
  layered allowlist, JSONL block log, launchd integration, CLI. Strict-mode
  only (everything's filtered, unknown hosts denied silently). See
  [CHANGELOG.md](CHANGELOG.md).

## In flight

_Nothing currently in active development. The macOS-first track is the
focus: public `catalog/` directory + v0.3 polish + NEFilter prototype._

## Planned

The public OSS edition stays macOS-first. Linux returns later as a
config-pack on top of [OpenSnitch](https://github.com/evilsocket/opensnitch)
rather than a native daemon port — building a second daemon to ride below
an existing MIT alternative isn't worth the maintenance cost.

### Next — public `catalog/` directory
- Aggregator for urlhaus / threatfox / OSV / GHSA / PhishTank
- Baseline allowlist (PyPI, npm, GitHub, Homebrew, common CDNs/LLM APIs)
- Exempt-app catalog (browsers, Slack, system services)
- Catalog format schema + GitHub Actions cron
- PR template + CODEOWNERS for community contribution

### v0.3 — polish & ergonomics
- Learn mode (record N minutes of traffic, propose allowlist additions)
- `egress-guard doctor` self-test for kernel rules + catalog freshness
- Per-project `.egress.toml` resolved from CWD of source process
- `egress-guard run -- <cmd>` strict-mode escape hatch
- Real-time `tail` via fsnotify/fsevents

### NEFilter prototype (parallel)
Validate the macOS Network Extension architecture in System-Extension
developer mode (no managed entitlement required for dev): TUN-immunity,
ClientHello byte access, `sourceAppAuditToken` process identity, p99
latency, Go ↔ Swift bridge. Stays MIT. Doesn't ship to users until
Apple's `content-filter-provider` entitlement is granted.

### v1.0 — ready for everyone
- Federated catalogs: Ed25519-signed feeds for exempt apps and known-bad lists,
  hourly/daily refresh
- CI Docker image (`egress-guard/ci:latest`) with strict-mode entrypoint
- Distribution: Homebrew tap
- Public threat-model review, documentation polish

### Linux — config-pack on top of OpenSnitch
Documentation + a small companion tool that takes the egress-guard public
catalog and generates OpenSnitch rules. Effectively: "egress-guard for
Linux, via OpenSnitch." Replaces the previously-planned Linux daemon port
(nftables / `SO_ORIGINAL_DST` / systemd unit). Effort: ~1 week. Tracked
in the issue tracker.

### v1.x — beyond the laptop
- Windows port (Windows Filtering Platform)
- Stack bundle (anon-proxy + egress-guard one-command install)
- Team-mode SaaS (shared allowlists, audit dashboard)
- Behavioral heuristics (process-tree awareness, anomaly detection)
- Browser extension or Chrome enterprise policy

See [TODOS.md](TODOS.md) for additional deferred items not on the version
roadmap (Grafana dashboard, strict-mode quickstart flag, etc.).
