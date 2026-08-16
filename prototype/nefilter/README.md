# NEFilter Prototype

## De-risk report

### Bridge latency

Measured on 2026-08-15 on an Apple M1 Pro using 10,000 round trips through
the live Unix-domain-socket bridge server with one persistent client connection:

- p50: 10.458 microseconds
- p99: 27.792 microseconds
- max: 662.417 microseconds

`BenchmarkBridgeRoundTrip` measured 10,144 ns/op, 752 B/op, and 15 allocs/op.

This is a transport-only result. The benchmark uses `StubResolver` and does not
include DNS binding, Security.framework audit-token lookup, or code-signature
verification. The runnable bridge uses the real resolver and a 256-entry
signature-verification cache; its end-to-end resolver latency has not been
benchmarked yet.

### Audit-token identity

On macOS, the bridge passes the full kernel-issued audit token to
`SecCodeCopyGuestWithAttributes` using `kSecGuestAttributeAudit`, then obtains
the executable path from that live guest. Security.framework therefore checks
pidversion instead of reducing identity to a reusable PID; an invalid token,
missing guest, or missing path drops the request.

The subsequent signature verifier remains path-based and cached. This prototype
does not yet extract Team ID and bundle ID directly from the dynamic
`SecCodeRef`, so it does not claim that the full signed identity is immune to an
executable-path replacement race after guest resolution.

### Runnable bridge

`-log` is optional. By default, decisions are written to
`~/Library/Caches/egress-guard/nebridge-decisions.log`. A successful launch emits
`nebridge: listening on <socket>` after the private Unix listener is created.

## Fail-closed contract (normative)

The Go bridge is the policy decision point; the NEFilterDataProvider is the
enforcement point. The provider MUST resolve every one of the following to
`.drop()`, never `.allow()`:

| Condition | Provider action |
|---|---|
| Socket path does not exist | `.drop()` |
| `connect()` to the socket fails | `.drop()` |
| Bridge closes the connection without responding | `.drop()` |
| Response frame fails to decode | `.drop()` |
| No response within the provider's verdict deadline | `.drop()` |
| Response verdict byte is any value other than `0` (allow) | `.drop()` |

Rationale: `PHILOSOPHY.md` section 4.3 says unsure fails toward the human,
never toward allow. There is no human in this path, so unsure fails toward deny.
A provider that allows on bridge unavailability converts every crash, restart,
or upgrade of the daemon into an unlogged open door, which is strictly worse
than not running the filter at all.

The Go side upholds the other half: it answers `VerdictDrop` on SNI-parse
failure, identity-resolution failure, frame-decode failure, and log-write
failure, and bounds every request read at `requestReadTimeout` so the provider's
deadline is not the first thing to fire.
