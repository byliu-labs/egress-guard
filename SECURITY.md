# Security Policy

## Reporting a vulnerability

For a security tool, *quietly* is usually better than a public issue. Please email the maintainer:

**boyu.liu47@gmail.com** — subject prefix: `[egress-guard security]`

I'll acknowledge within a few days. If we agree the issue is in-scope and exploitable, I'll work on a fix and credit you (with permission) in the release notes. If we agree it's out of scope, I'll explain why and you're free to publicize.

Please don't open public GitHub issues for vulnerabilities until a fix has shipped.

---

## Threat model

Short version: egress-guard defends against **unprivileged code on your machine that wants to send your secrets to a destination you didn't authorize.** It is a defense-in-depth layer against supply-chain compromise — not a substitute for an antivirus, EDR, code-signing requirements, or operating-system hardening.

### In scope

- **Compromised packages from public registries** (PyPI, npm, RubyGems, crates.io, Hex, etc.) attempting to exfiltrate credentials, SSH keys, environment variables, shell history, cloud config, or wallet files over TCP/443.
- **`.pth`-style auto-execution payloads** that run on every Python interpreter start.
- **`postinstall` / `preinstall` lifecycle scripts** in npm packages.
- **Malicious code that calls subprocess** (e.g., `subprocess.Popen(["curl", ...])`). The kernel rule catches the curl process the same as the parent — `HTTPS_PROXY` and friends cannot be unset to bypass.
- **DNS-poisoning attacks against well-known hostnames.** A poisoned IP for `api.example.com` doesn't help the attacker — the SNI in the TLS ClientHello must match for the legitimate destination to complete the handshake, and the SNI is what egress-guard filters on.

### Residual risks (in-scope but acknowledged)

- **Exec-into-exempt-binary impersonation** *(relevant once v0.2 ships the exempt-app catalog).* A malicious script could `execvp` into a binary whose code signature would otherwise pass the exempt check (e.g., a signed Apple binary loaded into a process originally spawned as `python`). Mitigations: the exempt list will use bundle identifiers + Apple Developer Team IDs, not just executable paths, so the impersonator must be running a real signed app — and most GUI apps misbehave when launched outside their normal lifecycle. Behavioral heuristics (parent-process awareness) land in v1.x.
- **A user who clicks "Allow always" on a malicious prompt** *(v0.2+).* The prompt UX rate-limits and defaults to deny on timeout, but ultimately the user is the decision-maker.
- **A botched release of egress-guard itself** that breaks legitimate workflows. Mitigation: v1.0 federated catalog model + signed feeds; until then, bundled defaults change only with version releases.

### Out of scope

- **Attackers who already have root.** With sudo, an attacker can `pfctl -F all` (macOS) or `nft flush ruleset` (Linux) and remove the daemon. egress-guard is a defense-in-depth layer for unprivileged compromise, not root.
- **Active local exploits** (kernel CVEs, etc.) that escalate privilege.
- **Exfiltration over channels we don't filter:** UDP, ICMP tunneling, raw sockets to arbitrary ports unless the user explicitly redirects them. Most real-world supply-chain malware uses HTTPS because it blends in with normal traffic; egress-guard targets that path. Strict-mode users who want to deny all non-443 outbound can layer additional pf/nftables rules; this is documented as an advanced topic.
- **Browser-level attacks.** Browsers are exempt by default (v0.2+); a malicious browser extension can exfiltrate. This is a separate problem with separate defenses (extension review, content security policy, Chrome enterprise policy). v1.x may add a complementary browser extension; v0.x does not.
- **TLS 1.3 Encrypted ClientHello (ECH) widespread deployment.** When SNI is encrypted, hostname filtering degrades. Currently rare; revisited when measurable. Plan: opt-in DoH-pinned mode + IP-range fallback.
- **Attackers with physical access to the machine.**
- **Side channels** (timing, traffic analysis).

### Attacker capabilities assumed

- Can publish a malicious package to a public registry.
- Can run code as the user (any code that the user installs and runs).
- Cannot escalate to root without a separate exploit.
- Cannot tamper with the kernel or pf/nftables ruleset.
- Cannot intercept TLS without already having a CA in the trust store.

### What egress-guard does NOT see

- Anything inside the encrypted TLS tunnel — request headers, request bodies, responses, cookies, form data, API keys in `Authorization` headers, etc. The daemon reads only the cleartext TLS handshake bytes (specifically the SNI extension in the ClientHello) and the destination IP/port from the kernel's NAT table.
- DNS lookups (the system resolver runs as normal; egress-guard doesn't intercept).
- Anything you do over UDP, ICMP, or non-443/80 ports.

If you're worried about the daemon itself being a privacy concern — the source is small, the dependencies are minimal (`stdlib + github.com/BurntSushi/toml` only), and the JSONL block log lives entirely on your machine. There is no network call from egress-guard to any maintainer-controlled service in v0.1.

---

## Known false-negative modes

Cases where a malicious connection can complete despite egress-guard:

1. **The attacker exfiltrates over UDP, ICMP, or a non-443/80 port.** Default pf rules cover 443 (and we plan to add 80 in v0.1.x). Strict-mode users can layer a deny-all pf rule on the bottom.
2. **The attacker's exfil destination is on the bundled allowlist.** E.g., a malicious package POSTs to a Gist or Pastebin (`gist.github.com` is a subdomain of `*.github.com` in the default allowlist). Documented limitation; mitigation in v1.x is per-process allowlists ("`curl` can talk to PyPI but `python` cannot talk to `gist.github.com`").
3. **The attacker reuses an already-allowed CDN host.** E.g., uploads to a public S3 bucket whose hostname matches `*.s3.amazonaws.com` (a common, often-allowlisted pattern). The exfil completes; later detection requires content inspection or anomaly detection, both out of scope for egress-guard.

These limitations are inherent to a hostname-allowlist primitive. The right defenses for the gaps are complementary: package-signing requirements (sigstore, npm provenance), runtime behavioral monitoring (Falco, eBPF probes), and content-aware DLP. egress-guard is intentionally one layer of a defense-in-depth stack, not the entire stack.

---

## Disclosure policy

- Please use the email above for initial contact rather than public issues.
- Provide a reproduction or proof-of-concept if you can. If you can't, that's fine — describe what you observed.
- I'll acknowledge within a few days. If you don't hear back within 7 days, feel free to escalate by opening a low-detail public issue ("emailed maintainer about a security issue, no response yet").
- We will work out a coordinated disclosure timeline together. Default is 90 days from acknowledgment to public disclosure, longer if the issue requires significant rework.
- Responsible reporters will be credited in the release notes (with permission). I cannot offer bounties.

Thank you for taking the time to make this project safer.
