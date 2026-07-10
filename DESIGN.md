# egress-guard — Design

> **Status:** Design draft, pre-implementation
> **Date:** 2026-04-30
> **Sister project to:** [anon-proxy](https://github.com/byliu/anon-proxy)

A lightweight cross-platform egress firewall that filters network traffic from
scripting and shell processes against curated allowlists, while leaving
everyday GUI apps alone. Stops supply-chain credential exfiltration out of the
box, prompts you only for genuinely ambiguous traffic, and lives nicely with
VPNs and corporate proxies.

---

## 1. Problem

In March 2026, a malicious release of `litellm` (1.82.8) shipped a `.pth` file
that auto-executed on Python interpreter startup, harvested SSH keys / cloud
credentials / shell history / wallet data, encrypted them, and exfiltrated to
`models.litellm.cloud` via a hardcoded `curl` POST. No `import litellm`
required: every Python process on a developer's machine became a credential
stealer.

This is not an isolated incident — supply-chain compromises against PyPI, npm,
RubyGems, and crates.io are now routine. The economic asymmetry is brutal:
attackers compromise one package, harvest credentials from thousands of
development machines and CI runners, and cash out on the access. Developer
workstations make the worst possible target: they have shell history with
production paths, AWS / GCP / Kubernetes credentials in plaintext config
files, SSH keys with no passphrase, and a steady stream of `pip install` /
`npm install` commands installing whatever the lock file says.

### What today's tools cover, and don't

| Tool | Stops a `curl → exfil.example.com`? | Catch |
|---|---|---|
| **Little Snitch** (mac, paid) | Yes, prompts | Mac-only, $59, prompt fatigue defeats security |
| **OpenSnitch** (Linux) | Yes, prompts | Linux-only, same prompt fatigue |
| **pf / iptables** (DIY) | Yes if configured | Almost nobody configures this; allowlist maintenance is painful |
| **Kubernetes NetworkPolicy** | Yes | Production / k8s CI only — not laptops, not GitHub Actions |
| **Cilium / Tetragon** (eBPF) | Yes, with L7 awareness | Production-grade overkill for one workstation |
| **Container egress proxies** | Yes | Only for containerized workloads |

The capability exists. The **drop-in, cross-platform, low-friction form
factor** for individual machines and small teams does not. Especially not one
designed around the realistic attack surface — scripting interpreters and
shell tools, not the user's web browser.

---

## 2. Goals

1. **Stop unprivileged credential exfiltration.** A compromised pip / npm
   package, a malicious shell script, or a poisoned `.pth` file cannot send
   data to a destination not on the allowlist.
2. **Default-on for non-experts.** The first-run experience is one sudo
   prompt during install, then it works. Sensible defaults keep prompt
   frequency low. A user who never opens the config file should still be
   protected and not aggravated.
3. **Don't break everyday apps.** Browsers, chat apps, streaming, video
   calls, system services — all exempt by default. The user should not
   notice egress-guard during normal computer use.
4. **Cross-platform.** macOS and Linux at v1; Windows later.
5. **Free and open source.** No license fees, auditable code, community
   catalogs.
6. **Compose with anon-proxy and other proxies.** anon-proxy is just another
   allowlisted destination from egress-guard's perspective. Corporate HTTP
   proxies and VPNs work alongside without architectural conflict.

### Non-goals (v1)

- Defending against an attacker who already has root. With sudo, they remove
  the rules. Threat model is unprivileged-user supply-chain compromise.
- Layer 7 inspection beyond TLS SNI. No HTTP header rewriting, no payload
  analysis, no certificate authority installation.
- Per-process per-destination rules (over-complex). We filter classes of
  process; allowlists are global / per-project, not per-process.
- Windows.
- CI runners. Separate sister effort, see §11.
- Resilience to TLS 1.3 Encrypted ClientHello (ECH) widespread deployment.
  Currently rare; revisited when measurable.
- Inspecting traffic that already goes through a user-installed local
  intercepting proxy (Charles, mitmproxy in transparent mode). We detect the
  conflict at install time and refuse rather than fight.

---

## 3. Architecture

```
                                                 ┌────────────────────────────────┐
                                                 │        egress-guardd           │
                                                 │   (unprivileged daemon)        │
                                                 │                                │
[any process]──TCP/443──┐                        │  1. socket → pid → exe         │
                        │                        │  2. exempt list?  ──yes──> splice (transparent)
                        ▼                        │  3. SNI from ClientHello       │
        ┌────────────────────────────────┐       │  4. allowlist hit? ──yes──> splice
        │   pf / nftables redirect       │──TCP──>  5. known-bad?      ──yes──> drop+notify
        │   (installed via `install`)    │       │  6. unknown?        ──prompt──> allow/deny
        └────────────────────────────────┘       │     (timeout default = deny)   │
                                                 └────────────────────────────────┘
                                                                │
                                                                ▼
                                                ┌────────────────────────────────┐
                                                │   block log + notification     │
                                                │   ~/.local/state/egress-guard/ │
                                                └────────────────────────────────┘
```

Three components, each independently small:

### 3.1 `egress-guard install` / `uninstall`

A short CLI command that writes (or removes) pf rules on macOS and nftables /
iptables rules on Linux. The single sudo moment in the user's life. Idempotent
and refuses to overwrite rules it didn't write (detected via a marker file and
hash). Output of `install` is a one-line summary: which rules were added,
where to look if something breaks.

The rule is conceptually simple:

- Match TCP outbound on port 443 and 80, source = any, destination = anywhere.
- Exclude loopback (`127.0.0.0/8`, `::1`) so the daemon's own splice
  connections don't loop forever.
- Redirect to `localhost:<daemon port>`.

On macOS this is a `pfctl` anchor file. On Linux it's an nftables `nat
output` chain (preferred) with iptables `OUTPUT` chain as a fallback for older
distros.

### 3.2 `egress-guardd` — the daemon

Runs as a normal user process at login (launchd `LaunchAgent` on macOS,
systemd `--user` unit on Linux). The kernel rule does the privileged work; the
daemon needs no special capabilities beyond reading `/proc` (Linux) or
calling `proc_pidpath` (macOS).

Per-connection flow:

1. Accept the TCP connection on the redirect port. Use `SO_ORIGINAL_DST`
   (Linux) or pf's `divert-to` lookup (macOS) to recover the *intended*
   destination IP and port the client tried to reach.
2. Identify the source process: read socket peer pid, look up executable
   path. (`proc_pidpath` on macOS, `/proc/<pid>/exe` on Linux.)
3. Match the executable against the **exempt list**. If exempt, immediately
   splice through to the original destination, no further inspection.
4. Read the first ~1500 bytes of the client → server stream. Parse the TLS
   `ClientHello` and extract the SNI extension. (For HTTP, read the `Host:`
   header.)
5. Resolve the SNI hostname against the layered allowlist (defaults → user
   global → per-project). On hit, splice through.
6. If the SNI is on the bundled known-bad list (typo-squatted package names,
   exfil endpoints from recent CVE feeds), drop with a *silent* notification
   and a high-priority log entry.
7. Otherwise: prompt. Default action on timeout = deny.

The daemon never decrypts anything. It looks at the TLS handshake bytes,
makes a routing decision, and either splices both directions of the TCP
stream byte-for-byte or sends a TCP RST so the client fails fast.

### 3.3 `egress-guard` CLI

Operations the user actually runs:

```
egress-guard install / uninstall
egress-guard start / stop / status / restart / doctor
egress-guard allow <hostname>          # add to global allowlist
egress-guard deny <hostname>            # add to global denylist
egress-guard exempt-app <bundle-id>     # add an app to exempt list
egress-guard learn <duration>           # log everything; propose additions
egress-guard review                     # interactive: review proposals from learn mode
egress-guard run -- <cmd>               # run cmd in a stricter "no new prompts, deny on miss" profile
egress-guard tail                       # follow block log
egress-guard catalog status / refresh / subscribe <url>   # federated catalog mgmt
```

No daemon API beyond reload-on-SIGHUP. Config files are the source of truth.

### 3.4 Fail-closed posture

If the daemon crashes or is killed, the kernel rules continue to redirect
traffic to the (now-dead) port. Connections fail with TCP RST. This is
**fail-closed** — protective but disruptive. To bound the disruption:

- The daemon process is supervised by `launchd` (macOS) and `systemd --user`
  (Linux) with `Restart=always`. Crash → restart in <1s.
- `egress-guard uninstall` is daemon-independent: it removes the kernel rules
  using only the privileged helper, working even when the daemon is dead.
- `egress-guard doctor` runs a self-test: kernel rules present, daemon
  responsive, catalog fresh, signing key valid. Outputs human-readable
  status. Used at install time and on demand.

If kernel rules are removed without the daemon's knowledge (e.g., manual
`pfctl -F` or macOS upgrade resetting `pf.conf`), the daemon detects the
missing rules at startup or via periodic self-check and refuses to claim
"protection active." `doctor` reports the gap loudly.

### 3.5 Daemon's own outbound

The daemon does not currently fetch catalog feeds, IOC feeds, telemetry, or
updates. There is therefore no production daemon-originated network path to
exempt today.

Do not add daemon-originated networking until the privilege model is explicit.
On macOS the LaunchDaemon remains root because `DIOCNATLOOK` opens `/dev/pf`
for every accepted connection. A pf owner rule for a separate service account
would not match that root process. Future fetches need a real design, such as
running only the fetch subprocess under a non-root credential or separating the
privileged pf lookup path from the long-lived daemon identity.

### 3.6 CI Docker image

`egress-guard/ci:latest` is a minimal Linux base image with the daemon
preconfigured for ephemeral CI runners. The kernel-rule story differs:

- The container's network namespace has `nftables` rules installed at
  container start (CAP_NET_ADMIN required, easily granted in GitHub Actions
  / GitLab Runner / CircleCI configs).
- The entrypoint script reads the project's `.egress.toml` and starts the
  daemon in **strict mode** (deny-on-unknown, no prompts — no human to
  prompt anyway).
- Default policy is denser than the laptop default: only project-allowlisted
  destinations + a small CI-specific list (the registry serving the runner's
  base image, the CI provider's artifact endpoints).

CI image and laptop daemon share the same binary. Only the entrypoint and
default policy differ.

### 3.7 Federated catalog updater

A small in-daemon component periodically fetches catalog feeds:

- **Default feed** (project-maintained): the canonical exempt list and
  known-bad list, refreshed daily and hourly respectively.
- **Subscribed feeds** (community): `egress-guard catalog subscribe <url>`
  adds a feed; daemon fetches and merges.
- Each feed entry is **Ed25519-signed** by the feed maintainer's key. The
  daemon verifies signatures against a pinned key file (`/etc/egress-guard/
  feed-keys.toml`) before applying the update.
- Cached versions persist on disk; if a fetch fails, the daemon keeps
  operating on the cache.
- Signature failure is loud: `egress-guard doctor` reports it, and the
  failing feed is quarantined (the cached version stays in effect; the
  feed is not auto-re-fetched until the user runs `catalog refresh`).
- **Key rotation**: feed maintainers can roll keys by publishing a
  `feed-keys` update signed by the old key authorizing the new one. Manual
  rotation (replace `feed-keys.toml`) is documented for emergencies.

### 3.8 IOC threat-feed integration

The known-bad list is augmented from public IOC feeds (urlhaus,
threatfox, GitHub Advisory Database). The daemon fetches each feed
hourly, normalizes hostnames, and merges into the active known-bad list.

- Per-feed isolation: a malformed entry in one feed cannot poison another.
- Hostname normalization: lowercased, IDN-decoded, trailing-dot stripped,
  rejected if it contains characters not in [a-z0-9.-].
- Out-of-scope hostnames are filtered (the daemon doesn't import C2
  addresses for malware classes irrelevant to laptop dev workflows; the
  filter is curated per-feed).
- Feed health surfaced in `egress-guard catalog status`.

---

## 4. Process identity layer

### 4.1 Exempt vs filtered

- **Exempt** = the daemon does not interfere with this process's traffic.
  Default exempt list ships with the package, curated.
- **Filtered** = traffic from this process is subject to the hostname
  allowlist and prompt UX. Default behavior for everything not exempt.

Default exempt list (macOS bundle IDs / Linux exec paths):

- **Browsers**: Safari, Chrome, Firefox, Edge, Arc, Brave, Opera
- **Communication**: Slack, Discord, Zoom, Teams, Signal, WhatsApp, Telegram
- **Productivity / SaaS clients**: Notion, Obsidian, Linear, Figma, Spotify,
  Apple Music, Things, Fantastical
- **Cloud sync**: Dropbox, OneDrive, Google Drive, iCloud, Box
- **macOS system services**: `nsurlsessiond`, `trustd`, `softwareupdated`,
  `mdmclient`, `apsd`, `cloudd`, captive-portal probe
- **Linux system services**: `NetworkManager`, `systemd-resolved`,
  `gnome-shell`, `update-notifier`

### 4.2 Filtered list (informational)

We don't actually maintain a "filter this" list — anything not exempt is
filtered. But the realistic attack surface is concentrated in:

- Scripting interpreters: `python`, `python3`, `node`, `ruby`, `perl`, `php`,
  `lua`, `Rscript`
- Shell tools that fetch: `curl`, `wget`, `httpie`, `aria2c`
- Shells when they make outbound connections via builtins: `bash`, `zsh`,
  `sh`, `fish`
- Package managers: `pip`, `npm`, `gem`, `cargo`, `go`, `mvn`, `gradle`,
  `composer`, `brew`, `apt`, `dnf`
- Git / SSH: `git`, `ssh`, `scp`, `sftp`, `rsync`
- Anything compiled and run from a user directory without a code signature

A typical non-developer's day produces ~zero filtered connections. A typical
developer's day produces hundreds, almost all of which hit the default
allowlist (PyPI, npm, GitHub, Homebrew, common LLM APIs, common cloud auth)
and pass without a prompt.

### 4.3 Resisting impersonation

Filename matching is not enough — a malicious binary could be named `Slack`
or `Safari`. We resist this with platform-native signature checks:

- **macOS**: verify code signature via the Security framework (`SecCodeCheckValidity`).
  Compare the team identifier (Apple Developer ID) against the entry in the
  exempt list. A binary named `Safari` not signed by Apple does not match.
- **Linux**: verify the executable belongs to a package owned by the
  distro's package manager (`dpkg -S`, `rpm -qf`) and the package signature
  is valid. Binaries running out of user directories never match exempt.

Where the platform offers no signature, the binary is treated as filtered.

### 4.4 The Python problem

A malicious `.pth` runs as the `python3` interpreter, which is signed by
Apple, Homebrew, or the distro. The signature exempts the *binary*, not the
*code*. So we cannot exempt scripting interpreters by signature — Python /
Node / Ruby are always filtered, regardless of provenance. This is intentional
and is the core of the threat model: scripting interpreters are the primary
attack surface, and treating them as filtered is what makes the protection
work.

---

## 5. Hostname filter

### 5.1 Source of identity

We rely on the TLS `ClientHello` SNI for hostname identification. SNI ships
in cleartext in TLS 1.2 and TLS 1.3 (without ECH). For plain HTTP, we use
the `Host:` header.

We do not perform DNS lookups, do not consult the system resolver during
filtering, and do not trust the destination IP — only the hostname the client
*claims* to be reaching. This means a DNS poisoning attack still sees the
filter applied: an attacker who poisons `api.anthropic.com` to point at their
server still has to put `api.anthropic.com` in the SNI to complete the
handshake — which the legitimate destination expects but the attacker's
server does too. The filter passes, the legitimate destination sees the
forwarded SNI, and the legitimate destination's TLS cert validates against
its own hostname. A poisoned IP without matching SNI causes the legit
destination to terminate the handshake; the attacker's IP would have to forge
the cert anyway, which is the broader CA problem and out of scope.

### 5.2 Layered allowlist

Resolution order, most specific wins:

```
1. Built-in known-bad list  →  always deny, no prompt
2. Per-project ./.egress.toml (CWD of source process)
3. User global ~/.config/egress-guard/allowlist.toml
4. Built-in defaults (shipped with the package)
5. Unknown → prompt
```

Hostname matching:

- Exact hostname matches a single FQDN.
- A leading `*.` allows any subdomain: `*.github.com` matches
  `api.github.com`, `objects.githubusercontent.com`, but not `github.com`
  itself (add separately if needed, or write `**.github.com`).
- A leading `**.` allows the registered domain and all subdomains.

### 5.3 Default global allowlist seed

Categories shipped with the package, all enabled by default unless the user
opts out:

- **Package registries**: pypi.org, files.pythonhosted.org, registry.npmjs.org,
  rubygems.org, crates.io, deb.debian.org, archive.ubuntu.com, formulae.brew.sh,
  ghcr.io, docker.io
- **Code hosting**: github.com, gitlab.com, bitbucket.org, codeload.github.com,
  raw.githubusercontent.com, objects.githubusercontent.com
- **LLM APIs**: api.anthropic.com, api.openai.com, generativelanguage.googleapis.com,
  api.x.ai, api.together.xyz
- **Cloud auth (well-known endpoints)**: sts.amazonaws.com, login.microsoftonline.com,
  oauth2.googleapis.com, accounts.google.com
- **Cert transparency / OCSP**: ocsp.apple.com, certs.godaddy.com, etc.

The catalog is just a TOML file; users can review, audit, and remove
categories they don't need.

### 5.4 Known-bad list

A short, conservative list of hostnames known to host current exfiltration
infrastructure or typo-squat package registries. Sourced from public CVE
feeds and security-research disclosures. Updated separately from the main
config. A hit on this list never prompts — silent drop, high-priority log
entry, optional opt-in webhook ping (e.g., to a Slack channel).

---

## 6. Prompt UX

The single most important design surface, because bad prompts mean the user
disables the daemon.

### 6.1 What triggers a prompt

A connection from a filtered process to a hostname that is:

- not on the allowlist,
- not on the known-bad list,
- not on a recent denylist within the same session.

### 6.2 What the prompt shows

```
┌──────────────────────────────────────────────────────────────────┐
│  egress-guard                                                    │
│                                                                  │
│  node (npm install foobar)                                       │
│  from /Users/boyu/projects/myapp (parent: zsh)                   │
│  is connecting to:                                               │
│                                                                  │
│      foobar-cdn.s3.amazonaws.com                                 │
│                                                                  │
│  This is a new destination. Allow?                               │
│                                                                  │
│  [ Allow once ]  [ Allow always ]  [ Deny ]  [ Deny always ]     │
│                                                                  │
│  ▼ More options                                                  │
└──────────────────────────────────────────────────────────────────┘
```

Required context, in priority order:

1. The process binary basename and command-line (truncated to ~80 chars).
2. The CWD of the process and the parent process name.
3. The destination hostname.
4. Whether the registered domain has been seen before from any process.

The "More options" disclosure includes:

- Allow `*.s3.amazonaws.com` (registered domain + subdomains).
- Mark this app as exempt going forward (only offered for non-scripting
  processes; never for `python`, `node`, etc.).

### 6.3 Behavior

- **Group by registered domain** within a 60-second window. If `node` hits
  three subdomains of `s3.amazonaws.com` in quick succession, one prompt
  covers them with the option to allow the whole registered domain.
- **Default action on timeout = deny**. A 30-second timeout. Connection
  receives TCP RST so the client fails fast; the user can re-run.
- **Coalesce parallel prompts**. If the user is unattended and 50
  connections queue up, do not generate 50 prompts. The first prompt covers
  the first connection; subsequent identical (process, registered-domain)
  pairs queue silently and the queue is shown in `egress-guard status`.
- **No in-prompt rate-limit cache.** The `Deny always` / `Allow always`
  buttons write a `**.{regdom}` pattern into the user allowlist (and the
  live in-memory allowlist), so subsequent connections to the same
  registered domain are decided by the allowlist layer before they ever
  reach the prompt path. This deliberately replaces the earlier "deny once
  caches for 24h" design — that design needed per-(process, regdom) scoping
  to avoid one process silencing another, which the v0.2 implementation
  initially got wrong; the symmetric `Deny always` covers the same use
  case more honestly with no scoping pitfall.

### 6.4 Implementation

- **macOS**: `osascript display dialog` with four buttons (`Deny`,
  `Deny always`, `Allow once`, `Allow always`). The default button is
  `Deny`; timeout returns the same. Originally specified as
  `UNUserNotification`, but the cgo dependency on Apple's
  `UserNotifications.framework` was traded away to keep the build pure-Go
  and cross-arch release binaries simple. The hard four-button cap of
  `osascript` is the binding constraint on action set size.
- **Linux**: `notify-send --action` (libnotify CLI), four matching actions.
  notify-send supports more actions in principle; we ship the same four as
  macOS to keep behavior symmetric across platforms.
- **Headless / SSH'd machines**: future work — the current notifiers
  return the timeout-deny default if no display server is available.

---

## 7. Configuration

### 7.1 File locations

```
/etc/egress-guard/                        # system-wide, owned by root
  defaults.toml                           #   shipped with the package
  known-bad.toml                          #   shipped, updated separately

~/.config/egress-guard/                   # user-global
  allowlist.toml                          #   user additions / removals
  exempt-apps.toml                        #   user additions to exempt list
  daemon.toml                             #   daemon settings (port, log level)

<project>/.egress.toml                    # per-project, lives in repo
```

### 7.2 Format

TOML for human writeability. Example `.egress.toml`:

```toml
# Project-specific allowlist for "myapp"
[allow]
hosts = [
  "api.openai.com",
  "*.s3.amazonaws.com",
  "registry.terraform.io",
]

[deny]
hosts = ["telemetry.example.com"]

# Optional: tighten or loosen for this project
[mode]
on_unknown = "deny"   # "prompt" (default) | "allow" | "deny"
```

### 7.3 Reload

`SIGHUP` to the daemon reloads all config files. `egress-guard reload` is a
convenience wrapper.

---

## 8. Observability

### 8.1 Decision log

Append-only structured log at `~/.local/state/egress-guard/blocked.log`
(filename kept for compatibility with existing tooling), JSON Lines — one
entry for EVERY connection the daemon adjudicates, not just denials:

```json
{"ts":"2026-04-30T03:21:14Z","decision":"deny","action":"deny",
 "reason":"unknown_host_timeout","trust_tier":"prompt",
 "pid":12345,"exe":"/usr/local/bin/python3","comm":"python3",
 "argv":["python3","-c","..."],"cwd":"/tmp","ppid":12340,"pname":"sh",
 "host":"models.litellm.cloud","dest_ip":"203.0.113.42","dest_port":443,
 "team_id":"","sig_valid":false}
```

`decision` is `allow`, `deny`, or `observe`. `observe` means the daemon ran in
`egress-guard start -observe` (shadow/observation) mode: the verdict was
computed and logged in `action`/`reason` but never enforced — the connection
always went through. `trust_tier` records how the verdict was reached:
`catalog_fact` (a maintained destination catalog, todo #26), `prompt` (the
user was actually asked), `default` (a static allowlist/denylist match or the
no-prompt fallback), or `model_opinion` (an advisory LLM guess, todo #31 —
never auto-enforced). `team_id`/`sig_valid` carry the process's code-signature
identity when available.

`egress-guard tail` follows it. `egress-guard status` summarizes the last
24 hours: counts of allow / deny / observe / prompt-deny by reason and
registered domain.

### 8.2 Notifications

Rate-limited per (registered-domain, action) pair: first hit per hour
notifies, subsequent identical hits log silently. A high-priority
notification is fired for known-bad hits regardless of rate.

### 8.3 Metrics endpoint (optional, off by default)

The daemon can optionally expose `localhost:<port>/metrics` in Prometheus
format for users running their own monitoring. Off by default to avoid
leaking process telemetry to anything that probes localhost.

---

## 9. VPN, proxy, and DNS compatibility

### 9.1 What works without configuration

| Setup | Works? | Why |
|---|---|---|
| Full-tunnel VPN (NordVPN, Mullvad, WireGuard, OpenVPN, IPSec) | Yes | pf/nftables fires before VPN encapsulation; daemon's own splice connection rides the VPN normally. |
| Tailscale (mesh) | Yes | Coordination is UDP/4xxxx, not redirected; app-level HTTPS over Tailscale gets filtered like any 443 traffic. |
| `HTTPS_PROXY=http://127.0.0.1:<port>` | Yes | Local proxy pattern; trivially compatible. |
| anon-proxy as upstream | Yes | Just another allowlisted destination. |

### 9.2 What needs explicit setup

| Setup | Issue | Resolution |
|---|---|---|
| Corporate HTTP proxy on a non-standard port | CONNECT goes to `corp-proxy:3128`; we don't redirect 3128. | Doc pattern: chain it. Set `HTTPS_PROXY=http://localhost:<egress-guard-port>` and add the corp proxy hostname to the allowlist as the upstream destination. |
| Charles / Proxyman / mitmproxy in transparent mode | Two tools fight over pf/nftables rules. | `egress-guard install` detects pre-existing rules from these tools at install time and refuses, points to docs. |
| DoH / DoT to a non-local resolver | SNI for `cloudflare-dns.com` / similar hits the filter. | Default allowlist includes the common DoH/DoT endpoints. Custom resolvers added via `egress-guard allow`. |
| TLS to private IPs (Tailscale-internal services on 443) | SNI may be a `*.ts.net` name or absent. | Allowlist `**.ts.net`; for the no-SNI edge case, add an IP-range exception (documented; rare). |
| Captive portals (hotel / airport wifi) | Sign-in domains aren't allowlisted. | Default allowlist includes captive-portal probes (`captive.apple.com`, `connectivity-check.ubuntu.com`, etc.); macOS captive-portal-detected state pauses filtering for the duration. |

### 9.3 What we don't try to handle

- A user running a transparent intercepting proxy *and* egress-guard
  simultaneously. Refuse at install time.
- Custom protocols on non-standard ports. v1 redirects 80/443 only;
  everything else passes unfiltered. Loosen via custom rules in `daemon.toml`.

---

## 10. Threat model

### 10.1 In scope

- Unprivileged code (running as the user) attempting to exfiltrate data over
  TCP/443 or TCP/80. Includes:
  - Malicious pip / npm / gem / cargo packages.
  - Compromised dependencies (transitive supply-chain).
  - Auto-executing files: `.pth`, `npm preinstall` scripts, post-install hooks.
  - User-run shell scripts from untrusted sources.
- Malicious code attempting to bypass via subprocess (e.g.,
  `subprocess.Popen(["curl", ...])`). The kernel rule catches the curl
  process the same as the parent.
- DNS-poisoning attacks against well-known hostnames (mitigated because the
  client still must claim a real hostname in SNI to complete handshake).

### 10.2 Residual risks (in-scope but acknowledged)

- **Exec-into-exempt-binary impersonation.** A malicious script could
  `execvp` into a binary whose code signature would otherwise pass the
  exempt check (e.g., a signed Apple binary loaded into a process
  originally spawned as `python`). The signature check passes; the
  daemon would mark the connection exempt. Mitigations: the exempt list
  uses bundle identifiers + Apple Developer Team IDs, not just executable
  paths, so the impersonator must be running a real signed app — and most
  GUI apps misbehave when launched outside their normal lifecycle. We
  document this as a residual risk and add behavioral heuristics
  (reparenting, missing parent app context) in v1.x.
- **A user who clicks "Allow always" on a malicious prompt.** Prompt
  copy and timeout-deny default reduce this; ultimately user agency is the
  decision-maker.

### 10.3 Out of scope

- Attackers who already have root. They can `pfctl -F all` (macOS) or `nft
  flush ruleset` (Linux) and remove the daemon. egress-guard is a
  defense-in-depth layer for unprivileged compromise, not root.
- Active local exploits (kernel CVEs, etc.) that escalate privilege.
- Exfiltration over channels we don't filter: UDP, ICMP tunneling, custom
  ports unless the user explicitly redirects them. Most real-world malware
  uses HTTPS because it blends in; egress-guard targets that path.
- Browser-level attacks. The browser is exempt; a malicious browser
  extension can exfiltrate. This is a separate problem with separate
  defenses (browser extension review, content security policy, etc.).
- TLS 1.3 ECH widespread deployment. When SNI is encrypted, hostname
  filtering degrades. Revisit when measurable.
- Attackers with physical access to the machine.
- Side channels (timing, traffic analysis).

### 10.4 Attacker capabilities assumed

- Can publish a malicious package to a public registry.
- Can run code as the user (any code that the user installs and runs).
- Cannot escalate to root without a separate exploit.
- Cannot tamper with the kernel or pf/nftables ruleset.
- Cannot intercept TLS without already having a CA in the trust store.

---

## 11. Out of scope for v1.0, planned

(Note: CI Docker image, federated catalogs, and IOC threat-feed integration
were originally listed here. Promoted to v1.0 scope after CEO review on
2026-04-30 — see §3.6, §3.7, §3.8.)

### 11.1 Windows

Different network stack (Windows Filtering Platform), different rule
plumbing, different process identity APIs. Architecturally compatible but
phase 2.

### 11.2 ECH resilience

Plan: when ECH is widely deployed enough to matter, add an opt-in mode that
uses pinned DoH for hostname resolution and IP-range filtering as a fallback.
Today this is over-engineering.

### 11.3 Per-process allowlists

"`curl` can talk to PyPI but `python` cannot." Sounds appealing, explodes
config complexity. Hostname-only in v1; revisit if user demand justifies it.

### 11.4 Stack bundle (anon-proxy + egress-guard)

Combined `brew install` / apt repo of the two sister projects. Wait for
both projects to stabilize independently first; package as a separate
effort post-v1.0.

### 11.5 Team-mode SaaS

Shared per-team allowlists, central audit dashboard, approval workflows
for new domains. Big bet — separate sister-of-sister project.

### 11.6 Behavioral heuristics

Process-tree-aware filtering, parent-of-parent context, anomaly detection on
allowlisted-domain traffic patterns. Better signal but heuristic; ship the
hostname-based primitive first.

### 11.7 Browser extension

Browsers are exempt by default; malicious browser extensions can still
exfiltrate. Closing this gap requires a complementary browser extension or
Chrome enterprise policy. Full separate product.

---

## 12. Open questions

These are flagged for the implementation plan to resolve, not the design.

1. **Implementation language.** **Decided: Go.** Single static binary,
   excellent stdlib for TCP and TLS-handshake parsing, easy macOS/Linux
   cross-compile, mature Homebrew/apt distribution story, fast startup, large
   contributor pool. Idiomatic for security daemons (Tailscale, Cloudflared,
   Cilium-agent). Confirmed during CEO review 2026-04-30.
2. **Daemon distribution.** Homebrew tap for macOS; `.deb`/`.rpm` for Linux;
   build-from-source for everything else.
3. **Default catalog of exempt apps**: how much does the v1 ship with vs.
   build via learn mode? Bias toward shipping a sensible catalog so that
   first-run on a stock developer machine produces ≤5 prompts in the first
   hour.
4. **Config-modification UX**: editing TOML files works for power users; is
   a small status-tray app worth shipping in v1, or does CLI suffice? Bias
   toward CLI in v1 to keep scope tight; status-tray app post-v1.0.
5. **Self-update / catalog-update mechanism**: how does the known-bad list
   stay current? Probably a simple HTTPS pull on daemon start + periodic
   refresh, signed with a project key.

---

## 13. Phased rollout

**v0.1 — bare minimum.** Daemon, install/uninstall, hostname allowlist with
bundled defaults, block log. No process-identity layer (everything is
filtered, no exempt apps yet) and no prompt UX (deny-by-default on miss).
Useful for people who explicitly want strict mode and accept that browsers
will need allowlist entries. Validates the core pipeline end-to-end.

**v0.2 — usability.** Process-identity layer, exempt list (bundled), prompt
UX with domain grouping and timeout-deny. This is the version that aims at
non-experts. Default-on UX achievable. **Shipped 2026-05-01.**

**v0.3 — polish.** Learn mode, per-project `.egress.toml`, `egress-guard
run` escape hatch, Linux desktop notifications, `egress-guard doctor`
self-test.

**v1.0 — ready for everyone.** Three pieces in parallel (per CEO review
2026-04-30):
- **Federated/signed catalogs** (§3.7): exempt and known-bad lists pulled
  from Ed25519-signed feeds with hourly/daily refresh. Default feed
  maintained by the project.
- **IOC threat-feed integration** (§3.8): urlhaus / threatfox / GitHub
  Advisory hostnames auto-merged into known-bad.
- **CI Docker image** (§3.6): `egress-guard/ci:latest`, same daemon binary,
  container-aware entrypoint, strict mode. Documented patterns for GitHub
  Actions / GitLab Runner / CircleCI.
- Distribution via Homebrew + apt; documentation; public threat-model
  review.

**v1.x — beyond the laptop.** Windows port, stack bundle with anon-proxy,
team-mode SaaS, behavioral heuristics, browser extension. See §11.

---

## 14. Why not just contribute to OpenSnitch?

OpenSnitch is excellent prior art and an obvious comparison. Two reasons we
don't simply contribute and stop:

1. **Linux-only.** Not a portability issue we can solve in OpenSnitch — the
   project is fundamentally an `nftables`/`netfilter` consumer. A
   cross-platform tool needs a different architecture.
2. **Different default philosophy.** OpenSnitch's defaults prompt for
   *every* new (process, destination) pair. Ours filter only scripting and
   shell tools, ship a curated exempt catalog, and use domain grouping to
   minimize prompts. The two designs serve different audiences. Forking
   OpenSnitch into "OpenSnitch but cross-platform with different defaults"
   is a larger undertaking than building a focused tool from scratch.

If the design lands well, contributing the SNI-filter and domain-grouping
ideas back upstream is a friendly thing to do.

---

## 15. Why a sister project, not a feature of anon-proxy

anon-proxy is a *content sanitizer*: it understands LLM API protocols, masks
PII before requests leave the device, and unmasks PII in responses. Its job
is rewriting, not gating.

egress-guard is a *transport gatekeeper*: it doesn't care what's in the
packet, only where it's going and from whom. Its job is allowlist
enforcement, not content rewriting.

These are complementary primitives. Bundling them would force every user to
adopt both — a user who only wants PII masking would still inherit the
kernel rules and prompt UX; a user who only wants egress control would
inherit a heavyweight ML model they don't need. Splitting them lets each
project stay focused, ship independently, and compose for users who want both.

Documentation should cross-link the two and recommend the combination as a
defense-in-depth pattern: anon-proxy sanitizes content; egress-guard
controls destinations; together they give "nothing leaves the box, and what
does leave is redacted."
