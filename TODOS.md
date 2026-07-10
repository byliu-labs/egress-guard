# TODOS

Deferred work for egress-guard. Items below are NOT in scope for v1.0; each was
considered during design and explicitly deferred. See `DESIGN.md` §11 for items
considered out of scope entirely (Windows, ECH resilience, per-process allowlists).

---

## v1.x candidates

### 1. Stack bundle (anon-proxy + egress-guard)

**What:** A single `brew tap` / apt repo that installs both projects together.
anon-proxy auto-allowlisted in egress-guard; sample combined config bundled.

**Why:** Composability story made tangible. "Private dev stack" = nothing
sensitive leaves the box, and what does is sanitized.

**Effort:** S (2 days human / ~1 hr CC) — pure packaging.

**Priority:** P3.

**Depends on:** Both projects shipped at v1.0 with stable distribution channels.

---

### 2. Strict-mode quickstart

**What:** `egress-guard install --strict` flag → installs with deny-on-unknown
defaults instead of prompt-on-unknown. For users who already understand the
trade-off and want maximum safety with no prompts.

**Why:** Power-user / security-team UX. Gives security folks a one-line
"run this on every dev box" command without the prompt-fatigue concern.

**Effort:** S — config preset + docs.

**Priority:** P2.

**Depends on:** v1.0 shipped.

---

### 3. Default Grafana dashboard

**What:** A bundled Grafana dashboard JSON that visualizes the daemon's
`/metrics` endpoint (block counts by registered domain, allow rate, prompt
rate, catalog freshness, feed health).

**Why:** Adoption story for security teams. "Show me what's been blocked
this week" without grepping the JSONL log.

**Effort:** S — dashboard JSON + brief docs.

**Priority:** P3.

**Depends on:** Decision on whether `/metrics` ships on by default in v1.0
(currently off by default).

---

## v2.x bets (bigger swings)

### 4. Team-mode SaaS

**What:** A SaaS where a team's per-project `.egress.toml` is centrally
managed. New domains require approval from a designated maintainer.
Audit log of all team decisions. Enterprise SSO.

**Why:** Solves "user A allowed `evil.com` quietly, the team didn't know."
Real value for security-conscious orgs. Possible commercial path for the
project.

**Effort:** L — backend, auth, dashboard, billing if commercial.

**Priority:** P3 (separate project scoping cycle).

**Depends on:** v1.0 adoption traction first.

---

### 5. Process-tree-aware filtering

**What:** When evaluating a connection, walk the process tree. `pip install`
invoked from `Terminal.app` is user-initiated; `pip install` invoked from
`python` running an auto-imported `.pth` is suspicious.

**Why:** Better signal on legitimate vs. malicious traffic. May reduce
prompt frequency without lowering protection.

**Effort:** M — process tree walking + heuristics + tests.

**Priority:** P2.

**Depends on:** v1.0 deployed; real-world prompt-frequency data to calibrate
heuristics against.

---

### 6. Anomaly detection on allowed domains

**What:** Track baseline traffic patterns to allowlisted domains; alert on
anomalies (a normally-low-volume host suddenly receiving large uploads, a
new subdomain pattern, off-hours traffic).

**Why:** Defense in depth even when the allowlist is right. Catches
compromised legitimate services.

**Effort:** L — baseline collection, anomaly model, alert tuning.

**Priority:** P3.

**Depends on:** Sufficient telemetry corpus to train baselines.

---

### 7. Browser extension / Chrome enterprise policy

**What:** Close the browser-exempt gap. Either a complementary browser
extension (Manifest V3) that allowlists domains for the user's browser, or
documentation + tooling to deploy Chrome enterprise policy that achieves the
same.

**Why:** Browsers are exempt by default in egress-guard's threat model;
malicious browser extensions can still exfiltrate. Closing this is a real
gap for security-conscious users.

**Effort:** L — full separate browser-extension product, ecosystem-specific
distribution (Chrome Web Store, Firefox AMO, etc.).

**Priority:** P3.

**Depends on:** v1.0 adoption; commitment to browser-extension maintenance.

---

## Implementation-plan inputs (not standalone TODOs)

The CEO review surfaced these as design constraints that should be addressed
in the implementation plan, not as separate backlog items:

- Block log dual-write to syslog (Linux) / unified logging (macOS) for
  tamper-resistance, alongside the JSONL file.
- Prompt timeout calibrated to 20s (leaves ≥10s splice slack vs. typical
  30s TLS client timeout).
- Burst-coalescing for parallel new-destination prompts: if a single
  process triggers >5 unique-registered-domain prompts within 60s, coalesce
  into a single "process X is making many new connections" prompt with a
  list view.
- SNI parser hardening: max ClientHello size bound, IDN normalization,
  rejection of names containing characters outside [a-z0-9.-].
- Catalog signing key rotation procedure: published rollover update signed
  by old key authorizing new key; manual rotation documented for
  emergencies.
- First-run gated self-test: `egress-guard install` runs `doctor` after rule
  install; rolls back if self-test fails.
- Daemon outbound exception via dedicated `_egress-guard` (mac) /
  `egress-guard` (linux) UID and pf/nftables `user !=` rule.
