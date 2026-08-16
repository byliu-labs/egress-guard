## Catalog Contribution

Use this template for changes under `catalog/`. Append `?template=catalog.md`
to the PR URL to select it.

### What This Adds Or Changes

<!-- One line per identity or host. -->

### Evidence

For each new `[[entry]]`, state what you verified and how:

- [ ] Identity anchor: `bundle_id`/`team_id` from `codesign -dvv`, or a stated
      `exe_basename` (name-only entries are capped at `confidence = "medium"`).
- [ ] Destination: the vendor doc, config default, or observed endpoint proving
      this host is legitimate for this identity.
- [ ] A reviewer can reproduce the evidence independently.

### Self-Check

- [ ] `confidence` is honest; `high` requires a signature anchor. Confidence is
      provenance only; daemon decisions do not change between `medium` and
      `high`.
- [ ] `schema_version = 1`.
- [ ] `go test ./internal/catalogbuild/... -v` passes locally.
- [ ] No secrets, keys, or internal-only content added.
