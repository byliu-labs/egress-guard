# Telemetry disclosure

egress-guard telemetry is off by default. It only turns on when you run:

```sh
egress-guard telemetry enable
```

Run `egress-guard telemetry disable` to turn it back off. Run
`egress-guard telemetry status` to see the current state.

## What is sent

When enabled, each "Allow Always" or "Deny Always" ratification sends one
`Report` to the configured endpoint. The default endpoint is
`https://telemetry.egress-guard.dev/v1/report`, and users can override it in
`telemetry.toml`.

| Field | Contents |
|---|---|
| `InstallUUID` | A random UUID generated once on your machine the first time you enable telemetry, reused for future reports. |
| `Identity` | The process identity you ratified: executable basename, Developer Team ID, bundle ID, and whether a signature was required. |
| `Host` | The exact hostname you ratified, in cleartext. |
| `Verdict` | `"allow"` or `"deny"`. |
| `SchemaVersion` | The report schema version. |

## What is never sent

- Process arguments, working directory, PID, or file paths.
- Connection payloads or TLS session bytes.
- `user_active` — whether someone had touched the keyboard or mouse recently.
  This is recorded in your local decision log so behavioural scoring can tell a
  3 a.m. beacon from you working at 3 a.m. It never leaves your machine.
- Any field beyond the five fields listed above.

## What telemetry is used for

Reports fill a maintainer review queue. Frequency affects review order only.
Reports never modify the baseline catalog automatically. Promotion always
requires a maintainer to attach independent evidence and explicitly approve the
candidate.
