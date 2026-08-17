# egress-guard

**Stop a malicious `pip install` from stealing your AWS keys, SSH keys, and `.env` secrets — without breaking your browser or your day.** A lightweight cross-platform egress firewall that filters scripting and shell traffic against curated allowlists while leaving everyday GUI apps alone. Once installed, the kernel redirects outbound TLS to a local daemon that reads the SNI hostname from the TLS ClientHello (no decryption), checks it against a layered allowlist, and either splices the connection through or drops it.

![Go 1.22+](https://img.shields.io/badge/go-1.22+-00ADD8.svg)
![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)
![Platform: macOS](https://img.shields.io/badge/platform-macOS-lightgrey.svg)
![Status: v0.2.0](https://img.shields.io/badge/status-v0.2.0-orange.svg)

```
   any process              kernel pf rule              egress-guardd
─────────────────         ──────────────────         ──────────────────
 curl, python,    ──443──>  redirect to     ──TCP──>  parse SNI from
 node, sh, ...              localhost:8443             TLS ClientHello
                                                            │
                                              ┌─────────────┼─────────────┐
                                              ▼             ▼             ▼
                                       allowlist hit?   known-bad?    unknown?
                                          splice         drop+log     drop+log
                                       (transparent)
```

---

## What prompted this

In **March 2026**, a malicious release of `litellm` (1.82.8) shipped on PyPI that auto-executed credential-stealing code every time the Python interpreter started — no `import litellm` required. It harvested SSH keys, `~/.aws/credentials`, `~/.gitconfig`, shell history, Kubernetes secrets, crypto wallet files, and cloud IMDS tokens, then encrypted and exfiltrated everything to `models.litellm.cloud` over HTTPS via a hardcoded `curl` POST. ([futuresearch.ai writeup](https://futuresearch.ai/blog/no-prompt-injection-required/))

Anyone who ran `pip install litellm` on that day on any machine — laptops, CI runners, dev containers — had their credentials silently stolen. Detection required noticing odd outbound TCP/443 to a domain you'd never heard of, in a process tree you weren't watching.

This kind of supply-chain compromise against PyPI / npm / RubyGems / crates.io is now routine. Per-incident damage is catastrophic; per-user incident rate is low and unpredictable. egress-guard is the insurance.

---

## Who is this for?

- **Developers who run `pip install`, `npm install`, `cargo install`, or `bundle install` on machines that also have cloud credentials, SSH keys, or `.env` files.** Which is most developers.
- **Security-conscious folks in small teams** without a dedicated security org, who can't realistically deploy Cilium or a paid endpoint security suite to one laptop.
- **ML researchers and data scientists** whose workflow is "pip install whatever the paper used and run the notebook" — high attack surface, often on machines with cloud creds for training infra.
- **Open-source contributors** who clone unfamiliar repos and run their build/test commands.
- **Anyone running CI workloads** on shelf-stable runners (planned for v1.0 via the CI Docker image — laptops first).

If you've ever felt mild dread typing `pip install` on a machine that has access to anything important, this is for you.

---

## Why not just use X?

| Tool | What it does | Why it's not quite right for this |
|---|---|---|
| **Little Snitch** (macOS, paid) | Application-level firewall with prompts | macOS-only, $59. Prompt fatigue: prompts on every (process, destination) pair from a fresh install — most users learn to click "Allow" reflexively, defeating the security. egress-guard ships a curated exempt-app catalog (browsers, Slack, system services) so it only filters scripting/shell traffic — the actual attack surface. *(Process identity + exempt catalog land in v0.2.)* |
| **OpenSnitch** (Linux, free) | Same model as Little Snitch | Linux-only, same prompt-fatigue problem. Excellent prior art — egress-guard borrows ideas. |
| **pf / iptables / nftables (DIY)** | Native kernel firewall with allowlist rules | Maintaining allowlists for PyPI, GitHub, npm, CDNs, auth providers, telemetry, etc. is genuinely painful. Almost nobody does it. |
| **Kubernetes NetworkPolicy / Cilium** | Pod / cluster egress allowlists | Production-grade overkill for one workstation. Doesn't help dev laptops or CI runners outside k8s (GitHub Actions, GitLab Runner). |
| **Container-only dev** (devcontainers, etc.) | Network-isolated workloads | Real defense, real lifestyle change. Many devs won't adopt; complementary, not a replacement. |
| **DNS sinkhole / hosts-file blocklist** | Reject lookups for known-bad domains | Trivially bypassed: malware hardcodes an IP address. DoH-in-app dodges entirely. Reactive — only catches known threats. |
| **"Don't run untrusted code"** | 🙏 | Not a security model. The whole supply-chain problem is that you trusted the package and it became hostile after a maintainer compromise. |
| **egress-guard** | Cross-platform, curated-default, hostname-allowlist firewall that filters scripting/shell processes specifically | One sudo prompt at install time (for the pf anchor; the user agent installs without sudo). Browsers/Slack/Spotify exempt by default *(v0.2)*. Sensible allowlist out of the box (PyPI, GitHub, npm, common LLM APIs). MIT-licensed, Go single-binary, free. |

---

## Quick demo

```bash
# Build, install kernel rules, then enable the user agent (two steps — see "Install" below for why)
make build
sudo ./bin/egress-guard install   # pf anchor (root)
./bin/egress-guard enable         # LaunchAgent (user — NOT sudo)

# Start the daemon (auto-started at login by launchd; running manually shown for clarity)
./bin/egress-guard start &

# In another terminal — watch decisions in real time
./bin/egress-guard tail
```

```jsonl
{"ts":"2026-04-30T15:30:01Z","action":"allow","host":"pypi.org","dest_ip":"151.101.0.223","dest_port":443}
{"ts":"2026-04-30T15:30:02Z","action":"allow","host":"files.pythonhosted.org","dest_ip":"151.101.1.63","dest_port":443}
{"ts":"2026-04-30T15:30:14Z","action":"deny","reason":"host_not_allowlisted","host":"models.litellm.cloud","dest_ip":"203.0.113.42","dest_port":443}
{"ts":"2026-04-30T15:30:14Z","action":"deny","reason":"host_not_allowlisted","host":"models.litellm.cloud","dest_ip":"203.0.113.42","dest_port":443}
```

The `pip install`s of legitimate packages succeeded. The malicious `.pth` payload's `curl` to `models.litellm.cloud` was dropped at the kernel layer — the connection never completed.

---

## One-click install (macOS app)

Prefer a menu-bar app over the CLI? Build the bundle and double-click it:

```bash
make app
open bin/EgressGuard.app   # first launch: right-click -> Open (unsigned build)
```

On first launch it asks for your admin password **once**, installs the pf anchor
and the daemon, and drops a 🛡️ into your menu bar. From there you can watch
recent blocks, allow the last blocked host, pause/resume protection, toggle
start-at-login, and **Uninstall** to remove every component behind one prompt.

The CLI and `make` targets below still work unchanged: the app is an optional
front end, not a replacement. The bundle is unsigned today; a signed/notarized
build with no right-click step is a drop-in once Developer ID credentials are
added to `packaging/mac/build-app.sh`.

---

## Prerequisites (v0.1.0)

- macOS 11 (Big Sur) or newer — Apple Silicon and Intel both supported
- Go 1.22+ to build from source (planned: Homebrew tap in v1.0)
- One-time `sudo` for installing pf rules

Windows and CI Docker support are on the [roadmap](ROADMAP.md). Linux support returns later as an OpenSnitch config-pack.

---

## Install

Download a prebuilt binary from the [release page](https://github.com/byliu-labs/egress-guard/releases/tag/v0.1.0), or build from source:

```bash
git clone https://github.com/byliu-labs/egress-guard
cd egress-guard
make build
sudo ./bin/egress-guard install   # step 1: pf anchor (requires sudo)
./bin/egress-guard enable         # step 2: user LaunchAgent (NOT sudo)
```

**Why two steps?** Install used to be one command — `sudo egress-guard install` did both halves. The kernel-rules half correctly ran as root, but so did the LaunchAgent install, which left the plist and state directory owned by root. The daemon (which runs as your user) then couldn't write its blocklog and crashed in a KeepAlive loop. Splitting the command guarantees each half runs at the right privilege level: `install` only writes the pf anchor, `enable` only writes the user agent and refuses to run as root.

The LaunchAgent makes the daemon auto-start at login. To run it manually right now:

```bash
./bin/egress-guard start
```

To remove cleanly (idempotent in either order):

```bash
egress-guard uninstall          # removes the LaunchAgent
sudo egress-guard uninstall     # removes the pf anchor
```

---

## Commands

| Command | What it does |
|---|---|
| `egress-guard install` | Installs pf anchor (kernel rules). Requires `sudo`. |
| `egress-guard enable` | Installs the user LaunchAgent. Run as your user — refuses sudo. |
| `egress-guard uninstall` | Removes whichever half matches your privilege level. Run twice (with and without `sudo`) to remove both. |
| `egress-guard start` | Runs the daemon in the foreground (normally launchd does this). |
| `egress-guard status` | Reports kernel rules + LaunchAgent + daemon state, and warns if a TUN-mode proxy is bypassing egress-guard. |
| `egress-guard allow <host>` | Adds a host to the user allowlist. Repeatable. |
| `egress-guard deny <host>` | Adds a host to the user denylist. Repeatable. |
| `egress-guard tail` | Follows the JSONL block log live. |
| `egress-guard catalog fetch [--system] [--pubkey <path>]` | Fetches and installs a signed public baseline catalog. Use `sudo egress-guard catalog fetch --system` for boot-resident daemon installs; unsigned remote catalogs are refused. |
| `egress-guard enroll` | Finds known dev tools, shows what each talks to, and pins them in one sitting. |
| `egress-guard review` | Reviews binaries that changed since you pinned them. |
| `egress-guard version` | Prints the version string. |

Hostname patterns support three forms:
- `api.openai.com` — exact match
- `*.github.com` — any subdomain (matches `api.github.com`, not `github.com`)
- `**.github.com` — registered domain plus all subdomains

---

## Configuration

| File | Purpose |
|---|---|
| (embedded) | Bundled default allowlist — LLM APIs, package registries, code hosting, cloud auth, captive-portal probes |
| `~/.config/egress-guard/allowlist.toml` | User-global overrides; the `allow` / `deny` subcommands write here |
| `~/.config/egress-guard/catalog-baseline.toml` | Signed baseline catalog for foreground/user-mode runs |
| `/var/db/egress-guard/.config/egress-guard/catalog-baseline.toml` | Signed baseline catalog for the boot-resident daemon; update with `sudo egress-guard catalog fetch --system` |
| `~/.local/state/egress-guard/blocked.log` | JSONL append-only decision log |
| `/etc/pf.anchors/egress-guard` | The pf anchor file — managed automatically by `install` / `uninstall`, do not hand-edit |
| `~/Library/LaunchAgents/com.byliu.egress-guard.plist` | The LaunchAgent for auto-start at login |

**Resolution order, most specific wins:** known-bad denylist → user denylist → user allowlist → bundled defaults → otherwise deny.

To override the bundled defaults entirely (e.g., remove the LLM APIs from default-allowed), copy the embedded `configs/defaults.toml` to `~/.config/egress-guard/allowlist.toml` and edit. Per-project `.egress.toml` is planned for v0.3.

---

## What gets filtered, and what doesn't (v0.1)

**v0.1 filters everything.** No process identity yet — every outbound TCP/443 connection from any process gets the SNI check and allowlist lookup. That includes your browser, which means **browser traffic to anything not on the default allowlist will be blocked** until you allowlist the hosts your browser visits.

In practice this means:
- Most package-manager and dev workflows just work (PyPI, npm, GitHub, common cloud auth are in the default allowlist)
- Casual web browsing is heavily restricted unless you allowlist domains as you go
- The malicious-package class of attack we care about is reliably stopped

**v0.2** introduces the process-identity layer and exempt-app catalog (browsers, Slack, Spotify, system services exempt by default). At that point the threat model becomes "filter scripting and shell processes specifically; leave the user's everyday apps alone." That's when the project becomes friendly to non-developers.

If v0.1's strictness is too aggressive for your machine, the friction-free fix is to wait for v0.2 (next milestone — see [ROADMAP.md](ROADMAP.md)).

---

## Threat model

Short version: defends against **unprivileged code on your machine that wants to send your secrets to a destination you didn't authorize.** That covers compromised PyPI / npm / RubyGems / crates.io packages, malicious shell scripts run from untrusted sources, post-install hooks, and `.pth`-style auto-execution payloads.

Out of scope: an attacker who already has root, kernel exploits, side channels, browser extensions, exfiltration over UDP / ICMP / non-443 ports the user hasn't redirected.

The full model is in [SECURITY.md](SECURITY.md) — including residual risks (e.g. exec-into-exempt-binary impersonation), and the disclosure policy.

---

## FAQ

### Does this decrypt my TLS traffic?

No. egress-guard reads only the SNI hostname from the TLS ClientHello — which is in cleartext on the wire because the server needs it to pick a cert. We never install a CA cert, never break certificate pinning, never see anything inside the encrypted tunnel.

### Will it break my VPN?

Tested-clean: full-tunnel VPNs (NordVPN, Mullvad, WireGuard, OpenVPN, IPSec), Tailscale (UDP coordination unaffected; app-level HTTPS over Tailscale gets filtered like any 443 traffic). The kernel rule fires before the VPN encapsulates the packet, so the daemon's own splice connection rides the VPN normally.

Needs explicit setup: corporate HTTP proxies on non-443 ports (set `HTTPS_PROXY=http://localhost:8443` and put the corp proxy hostname in the allowlist), local intercepting proxies in transparent mode (Charles, Proxyman — refused at install time), DoH/DoT to non-local resolvers (allowlist the resolver hostname).

### Does it work with sing-box / ClashX / V2Ray / other TUN-mode transparent proxies?

**No, today** — and the failure is silent. If you're running a TUN-mode transparent proxy, the kernel routes all outbound TCP through that tool's `utun*` interface *before* PF's redirect rule gets a chance to fire. egress-guard's daemon stays running, the install command still reports success, but no traffic ever reaches the daemon, so it enforces nothing.

How to tell you're affected: `route -n get default` reports `interface: utun*`, or `host example.com` returns an address in `198.18.0.0/15` (a common FakeIP range). If either matches, egress-guard is a no-op.

What to do: either stop the TUN proxy when you want egress-guard's protection, or rely on the TUN proxy's own allowlist features. Both tools fundamentally want to be the kernel's outbound gatekeeper, and PF can only have one winner.

The architectural fix is to move egress-guard from PF to a macOS Network Extension (`NEFilterDataProvider` for socket-layer filtering, or `NEDNSProxyProvider` for DNS-layer filtering). Either would sit before the routing decision and coexist with TUN proxies. This is a real shift — System Extension packaging, Apple Developer Program enrollment, a managed-entitlement request to Apple — and not committed to any specific version. If this is a blocker for your setup, open an issue.

### Why does it need sudo?

Once. To install pf rules at the kernel layer. After that, the daemon runs unprivileged as you. Uninstall is also one sudo. The reason it has to be at the kernel layer (rather than just an `HTTPS_PROXY` env var) is that malicious code can trivially `unset HTTPS_PROXY` before exfiltrating; a kernel rule cannot be bypassed from userspace.

### Won't this break my browser?

In v0.1, yes, partially — browsers get filtered too, and you'll need to allowlist the domains you visit. v0.2 adds process-identity-based exempt-app handling so browsers are exempt by default. That's the next milestone.

### Can I disable it temporarily?

Yes:
```bash
sudo pfctl -a egress-guard -F all   # flush our pf anchor's rules; daemon keeps running but does nothing
```
Re-enable:
```bash
sudo /usr/local/bin/egress-guard install   # rewrites the anchor
```

For a clean uninstall, use `sudo egress-guard uninstall`.

### What hostnames are in the default allowlist?

LLM APIs (`api.anthropic.com`, `api.openai.com`, etc.), package registries (`pypi.org`, `registry.npmjs.org`, `crates.io`, `rubygems.org`, `formulae.brew.sh`), code hosting (GitHub, GitLab, Bitbucket), well-known cloud auth endpoints (AWS STS, Azure AD, Google OAuth), and captive-portal probes (so hotel wifi sign-in still works). Full list: [`configs/defaults.toml`](configs/defaults.toml). Edit `~/.config/egress-guard/allowlist.toml` to override.

### How do I see what's been blocked?

```bash
egress-guard tail
```

The block log is JSONL at `~/.local/state/egress-guard/blocked.log`. Every decision (allow and deny) is logged with hostname, original destination IP/port, and reason.

### Is there a Linux version?

Not currently. The roadmap calls for Linux to return as a config-pack on top of [OpenSnitch](https://github.com/evilsocket/opensnitch) — a companion tool that translates the egress-guard catalog into OpenSnitch rules — rather than a native daemon port. Building a second Linux daemon to ride below an existing MIT alternative isn't worth the maintenance cost. Windows is on the roadmap as v1.x; the Windows Filtering Platform has different semantics that need a fresh design pass.

### Does this work in CI?

Not yet. The kernel-rule pattern doesn't fit GitHub Actions / GitLab Runner / CircleCI directly. v1.0 will ship a Docker base image (`egress-guard/ci:latest`) with the daemon preconfigured for ephemeral runners, configured via a project's `.egress.toml`. See [ROADMAP.md](ROADMAP.md).

### How is this different from anon-proxy?

[anon-proxy](https://github.com/byliu-labs/anon_proxy) is a *content sanitizer* — it understands LLM API protocols and masks PII before requests leave the device. egress-guard is a *transport gatekeeper* — it doesn't care what's in the packet, only where it's going and from whom. Complementary primitives, separate projects. Run both for "nothing leaves the box, and what does leave is redacted."

### What if you don't ship v0.2?

The current v0.1 code is small (~3 MB binary, focused Go modules) and covers the core security primitive end-to-end. Anyone can fork and continue the roadmap. MIT license, no contributor agreement, no telemetry, no upstream service. Source of truth is the repo.

### Will egress-guard see my passwords / API keys / form submissions?

No — see "Does this decrypt my TLS traffic" above. The daemon sees only TLS handshake bytes and SNI hostnames. Everything else is opaque.

---

## Reporting a vulnerability

See [SECURITY.md](SECURITY.md). For a security tool, *quietly* is usually better than a public issue — please email the maintainer first.

---

## Roadmap

- **v0.1** — darwin foundation (kernel pf rules, SNI filter, layered allowlist, JSONL block log) — **shipped 2026-04-30**
- **v0.2** — Process-identity layer + exempt-app catalog + prompt UX (the "default-on for non-experts" milestone) — **shipped 2026-05-06**
- **Next** — public `catalog/` directory (community-contributable threat feeds + baseline allowlist + exempt-app catalog), v0.3 polish (Learn mode, `doctor` self-test, per-project `.egress.toml`, escape-hatch `run` command, fsnotify `tail`), NEFilter prototype
- **v1.0** — Federated/signed catalogs, IOC threat-feed integration, CI Docker image, Homebrew tap
- **Linux** — OpenSnitch config-pack (companion tool, not a daemon port)
- **v1.x** — Windows port, anon-proxy bundle, team-mode SaaS, behavioral heuristics

Full version-by-version detail in [ROADMAP.md](ROADMAP.md). Deferred backlog beyond the version plan: [TODOS.md](TODOS.md).

---

## Documentation index

| Doc | Purpose |
|---|---|
| [DESIGN.md](DESIGN.md) | Full architecture, threat model, configuration, VPN/proxy compatibility, attacker model |
| [ROADMAP.md](ROADMAP.md) | Version-by-version roadmap |
| [CHANGELOG.md](CHANGELOG.md) | What shipped, when |
| [SECURITY.md](SECURITY.md) | Threat model + disclosure policy |
| [TODOS.md](TODOS.md) | Deferred backlog |

---

## Development

The project uses a small `Makefile` because two source files are generated
from configs at build time. Use the make targets — bare `go build` /
`go test` won't find the generated files on a fresh checkout.

```bash
make build           # builds bin/egress-guard for the host platform
make test            # runs unit tests under -race; embeds first
make test-integration  # darwin-only sudo-gated end-to-end tests
make clean           # removes bin/ and the generated embed file
```

Under the hood `make embed` copies `configs/defaults.toml` into
`internal/config/defaults_embedded.toml` (gitignored, generated on
demand). Running `go test ./internal/tail/` directly works fine — the
new package has no embed dependency — but anything touching
`internal/config` or building the binary needs the embed step first.

---

## License

[MIT](LICENSE) © Boyu Liu. Issues and PRs welcome — this is a young project and feedback is the fastest way to improve it.
