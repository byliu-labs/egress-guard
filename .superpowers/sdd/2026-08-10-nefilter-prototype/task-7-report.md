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
| `GOCACHE=/tmp/egress-guard-gocache make test` | NeBridge package passed; full suite failed in two existing prototype smoke tests |
| Focused prototype smoke tests | Reproduced the same Unix-socket timeout |

The full-suite failure was:

```text
--- FAIL: TestNebridgeProto_Smoke
    main_test.go:27: nebridge-proto did not listen on .../s/s
--- FAIL: TestNebridgeProto_UsesBaselineCatalog
    main_test.go:90: nebridge-proto did not listen on .../s/s
```

The only `cmd/nebridge-proto` change is the required static declaration of its
resolver variable as `nebridge.IdentityResolver`; the runtime construction and
stub-selection branches are unchanged. The timeout remains unresolved here and
was not modified because it belongs to the earlier prototype-command task.

## Files changed

- `internal/nebridge/resolver.go`
- `internal/nebridge/resolver_darwin.go`
- `internal/nebridge/resolver_default.go`
- `internal/nebridge/resolver_darwin_test.go`
- `cmd/nebridge-proto/main.go`

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

## Concern

The complete `make test` suite is not green because the two existing
`cmd/nebridge-proto` socket smoke tests time out. The Task 7 focused test and
required Linux build are green.
