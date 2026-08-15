# NEFilter Prototype

## De-risk report

### Bridge latency

Measured on 2026-08-15 on an Apple M1 Pro using 10,000 round trips through
the live Unix-domain-socket bridge server with one persistent client connection:

- p50: 10.458 microseconds
- p99: 27.792 microseconds
- max: 662.417 microseconds

`BenchmarkBridgeRoundTrip` measured 10,144 ns/op, 752 B/op, and 15 allocs/op.
