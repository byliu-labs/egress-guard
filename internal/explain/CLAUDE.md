# internal/explain — model-generated egress explanations

<!-- L2 leaf. Delta only. Registered in docs/context-map.yaml. -->

`internal/explain` owns the data shape of a model's opinion about an egress event, and an
HTTP explainer that produces one. It exists so a guess can be labeled *as a guess* beside
catalog facts in the prompt.

It deliberately owns no policy: an explanation never decides allow/deny.

## Interfaces

`New(text, confidence, evidence, never)` builds an `Explanation`.
`NewHTTPExplainer(cfg, transport)` + `ConfigFromEnv()` provide the HTTP-backed implementation.

## Contracts & gotchas (package-specific)

- **API mode refuses plain HTTP.** Sending egress metadata to a remote endpoint over an
  unencrypted channel is the exact leak this product exists to prevent; local mode is the
  only one that skips authorization, and it is local-only.
- **Responses are size-capped and non-OK is an error.** An explainer must never hang or
  stream unbounded text into a modal dialog. Errors here degrade to "no explanation" —
  which still denies, per the root law — never to "allow because we could not check."
- **Explanations are advisory input to `prompt`, not a confidence source.** Do not let an
  explanation raise a catalog confidence level or populate a `never` list that the
  decision path reads as fact.
- **What leaves the machine here is a privacy surface.** Adding a field to the request
  payload changes what a user's machine tells a remote endpoint about its own processes;
  treat it as a disclosure change, not a refactor.

## Related docs (up the tree)

- Root `CLAUDE.md` — "model opinions are labeled, never merged into facts"
