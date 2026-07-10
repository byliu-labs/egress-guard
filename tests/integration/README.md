# Integration Tests

This directory contains integration and end-to-end tests for egress-guard.

## v0.1 Integration Tests

The existing `e2e_darwin_test.go` covers v0.1 functionality on darwin platforms. These tests require the binary to be built and the daemon to be installed and started with root privileges.

## v0.2 Integration Tests

v0.2 adds tests for the new process-identity, code-signature, and prompt subsystems.

### Running v0.2 e2e Tests

To run the v0.2 end-to-end test suite on darwin:

```bash
sudo egress-guard install
egress-guard start &
EGRESS_GUARD_E2E=1 go test -tags="darwin integration" ./tests/integration/... -v -run TestV02
```

Prerequisites:
- macOS / darwin platform
- `egress-guard` binary built (run `make build` from repo root)
- Daemon installed and started (the first two commands above)
- `EGRESS_GUARD_E2E=1` environment variable set to enable the tests

The tests verify:
1. Allowed hosts continue to work (regression test for v0.1 behavior)
2. Prompt "Allow once" action lets a connection through
3. Prompt timeout defaults to deny
4. Burst coalescing when many domains are queried quickly
