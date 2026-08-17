# Known-good identity catalog format

This document specifies the on-disk format for egress-guard's known-good
identity catalog (`internal/catalog`, Go 1.22, TOML). It is aimed at
contributors who want to add or review `baseline`-layer entries in this public
repository.

This document defines the format only. It does not ship seed content. The
baseline catalog's actual entries are curated separately and reviewed against
the bar below before merge.

## Why this exists

An allowlist says "reach this host." A catalog entry says more: "this specific,
verified process identity legitimately reaches this host, and here is why."
That distinction matters because a pinned catalog entry is a fact the daemon
can act on silently, while an unpinned entry can only explain the prompt.

A catalog fact is deterministic and evidence-backed. A model opinion from a
future explainer is advisory and cannot become a catalog fact without a human
ratifying it first.

## Shape

One entry, in TOML:

```toml
[[entry]]
schema_version = 1
layer          = "baseline"
confidence     = "high"
evidence       = "codesign -dvv verified; TeamID EQHXZ8M8AV is Google's own Apple Developer ID for Chrome, cross-checked against Google's published Team ID list."
explanation    = "Chrome checks for updates and syncs bookmarks with Google's own infrastructure."
never          = ["update.googleapis.com.evil-lookalike.example"]

[entry.identity]
bundle_id = "com.google.Chrome"
team_id   = "EQHXZ8M8AV"

[[entry.expected_destinations]]
host = "update.googleapis.com"
why  = "Chrome auto-update channel"

[[entry.expected_destinations]]
host = "clients2.google.com"
why  = "Chrome component and extension updates"
```

## Fields

| Field | Required | Notes |
|---|---|---|
| `schema_version` | yes | Must equal the loader's `CurrentSchemaVersion`, currently `1`. Unknown versions are rejected outright, not best-effort parsed. |
| `layer` | yes | One of `baseline`, `pro`, or `user`. `baseline` is this repo's community-contributable layer; `pro` is for private additions; `user` is for local ratifications. |
| `confidence` | yes | `high` or `medium` only. There is no `low`; an entry too weak to trust at `medium` does not belong in the catalog. |
| `evidence` | yes | A sentence describing why this is trusted: a signature you verified, vendor documentation, or a published Team ID list. "It seemed to work" is not evidence. |
| `explanation` | yes | The plain-English sentence a drift prompt shows the user. Write it for someone who has never heard of this process. |
| `never` | no | Hostnames this identity should never reach. This turns the entry into an anomaly detector for a legitimate identity contacting an illegitimate destination. |
| `entry.identity.exe_sha256` | no | SHA-256 of the executable bytes. When present, the runtime binary hash must match exactly. |
| `entry.identity.bundle_id` | no | Bundle identifier. When present, the runtime bundle ID must match exactly. |
| `entry.identity.team_id` | no | Signing team identifier. When present, the runtime signing team must match exactly. |
| `entry.identity.exe_basename` | conditional | At least one identity field is required. Basenames are useful prompt labels, but baseline/pro basename-only entries cannot silently allow traffic. |
| `entry.identity.signed_required` | no | Hint that this identity should only ever appear signed; reserved for future enforcement. |
| `entry.expected_destinations[].host` | no | Hostnames this identity legitimately contacts. `Lookup` only reports a found expected destination when the queried host is explicitly listed. |
| `entry.expected_destinations[].why` | no | One-line reason for the destination. |

## Confidence Floor

An identity anchored only by `exe_basename`, with no `exe_sha256`, `team_id`,
or `bundle_id`, cannot produce a silent daemon allow from the `baseline` or
`pro` layers. Renaming a binary to match a basename costs an attacker nothing.
Forging a binary hash, Developer ID, or bundle ID match does not.

The loader still accepts name-only `medium` entries so prompts can carry human
curated explanations for common tools. `Lookup` therefore reports two separate
facts: whether an entry was found for prompt context, and whether that entry is
authoritative enough to decide without asking. Confidence is descriptive
provenance, not a decision gate. The daemon's trust boundary for catalog allows
is a signed catalog artifact plus an explicit destination list plus an identity
pin. The local `user` layer records explicit user ratifications, but a hashless
ratification is still prompt context only; uncertainty must not become silent
authority.

## Match Rules

Lookup uses conjunctive identity fields:

1. Every identity field set by the entry must match the runtime identity.
2. If the entry sets none of `exe_sha256`, `team_id`, or `bundle_id`, it may be
   found for prompt context but is not authoritative unless it is in the local
   `user` layer.
3. If the entry also sets `exe_basename`, that basename must match too.

Host matching is exact after lowercasing and trimming one trailing dot. Version
1 has no wildcard or suffix matching.

An identity match alone is not enough for `Lookup` to return found. The queried
host must appear in either `expected_destinations` or `never`.

## Contribution Bar

A baseline PR must include real `evidence` and an honest `confidence`.
Reviewers should be able to reproduce the evidence, such as by running
`codesign -dvv` on the app themselves or finding the vendor's published Team
ID. If you cannot point to a concrete check, the entry is not ready.

## What This Cannot Do

SNI is client-controlled. A process can claim any hostname in its TLS
ClientHello; the daemon observes it, it does not cryptographically verify it.
Optional DNS binding can narrow this by binding the claimed hostname to a
resolved destination IP, but it mitigates rather than eliminates spoofing risk.

A catalog entry cannot stop exfiltration to a host that is also legitimately
allowlisted. If Chrome is expected to reach `clients2.google.com` and an
attacker tunnels stolen data through a request to that same host, the catalog
cannot distinguish that from normal traffic. `never` catches the wrong-host
case; it does not catch a legitimate destination used illegitimately.
