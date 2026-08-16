# Task 7 Report: Darwin audit-token resolver

## Implemented

- Added Darwin cgo resolution from the fixed `[32]byte` audit token to a PID
  with `audit_token_to_pid` from libbsm.
- Resolved the executable with `proc_pidpath` from libproc and returned
  `ProcInfo{PID, Exe, Comm: filepath.Base(Exe)}`.
- Verified the executable with the configured `signature.Verifier`, falling
  back to `signature.Default()` when none is supplied.
- Replaced the Task 6 placeholder with the concrete `SystemResolver` API and
  retained fail-closed non-Darwin behavior in a build-tagged implementation.
- Added a Darwin own-token test. It encodes the documented `audit_token_t`
  `val[5]` PID field using native endianness; cgo is unsupported in Go
  `_test.go` files, so the test cannot use an `import "C"` helper directly.

## RED evidence

Command:

```text
GOCACHE=/tmp/egress-guard-gocache go test ./internal/nebridge/ -run TestSystemResolver_OwnToken -v
```

Output before implementation:

```text
=== RUN   TestSystemResolver_OwnToken
    resolver_darwin_test.go:29: Resolve: nebridge: system identity resolution is unavailable
--- FAIL: TestSystemResolver_OwnToken (0.00s)
FAIL
FAIL    github.com/byliu-labs/egress-guard/internal/nebridge    3.243s
FAIL
```

The first invocation without `GOCACHE` was blocked before compilation because
the shared Go cache was not writable.

## GREEN evidence

Command:

```text
GOCACHE=/tmp/egress-guard-gocache go test ./internal/nebridge/ -run TestSystemResolver_OwnToken -v
```

Output:

```text
=== RUN   TestSystemResolver_OwnToken
--- PASS: TestSystemResolver_OwnToken (0.00s)
PASS
ok      github.com/byliu-labs/egress-guard/internal/nebridge    0.461s
```

Non-Darwin compatibility command:

```text
GOCACHE=/tmp/egress-guard-gocache GOOS=linux go build ./internal/nebridge/
```

Output: exit 0 with no build output.

Formatting and diff checks also passed:

```text
gofmt -d internal/nebridge/resolver.go internal/nebridge/resolver_darwin.go internal/nebridge/resolver_default.go internal/nebridge/resolver_darwin_test.go cmd/nebridge-proto/main.go
git diff --check
```

## Tests run

| Command | Result |
| --- | --- |
| Focused Darwin own-token test | Passed |
| Linux `go build ./internal/nebridge/` | Passed |
| `GOCACHE=/tmp/egress-guard-gocache make test` | Passed |
| `GOCACHE=/tmp/egress-guard-gocache make build` | Passed |
| `GOCACHE=/tmp/egress-guard-gocache go test -race -count=1 ./internal/nebridge ./cmd/nebridge-proto -v` | Passed |
| `GOCACHE=/tmp/egress-guard-gocache go test -race -count=1 ./internal/daemon -v` | Passed |
| `GOCACHE=/tmp/egress-guard-gocache go test -race -count=1 ./internal/tlsparse -v` | Passed |
| `GOCACHE=/tmp/egress-guard-gocache GOOS=linux go build ./internal/nebridge/` | Passed |
| `GOCACHE=/tmp/egress-guard-gocache go vet ./...` | Passed |

During finish, the full-suite run initially exposed three environment/test-harness
issues:

- `cmd/nebridge-proto` smoke tests used a 2s child-process readiness deadline,
  which was too tight under whole-suite race/build load. The deadline is now 10s.
- `internal/daemon` unit coverage expected live persistence attribution for the
  current process. It now uses the existing persistence stub hook so it tests
  `entryFor` deterministically.
- Darwin persistence integration checks now skip when the sandbox blocks the
  exact read-only process tools they depend on (`ps` and `launchctl`), while pure
  classifier coverage still runs.

## Files changed

- `internal/nebridge/resolver.go`
- `internal/nebridge/resolver_darwin.go`
- `internal/nebridge/resolver_default.go`
- `internal/nebridge/resolver_darwin_test.go`
- `cmd/nebridge-proto/main.go`
- `cmd/nebridge-proto/main_test.go`
- `internal/daemon/decision_persist_test.go`
- `internal/persist/classify_darwin_test.go`
- `internal/persist/persist_darwin_test.go`

## Self-review

- Correctness: own-token test proves PID decoding, `proc_pidpath` executable
  lookup, basename command, and configured signature identity return.
- Security: C receives only the fixed-size token, uses no shell strings, and
  all lookup or verification errors return an error rather than allowing a
  connection.
- Compatibility: the non-Darwin resolver remains an explicit fail-closed stub
  and builds for Linux.
- Scope: the command-package edit is needed solely because the exact concrete
  constructor return type otherwise prevents assignment of `StubResolver`.
