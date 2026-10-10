# T06 — WARP perf: preflight, port-gate, sockets, jitter

Spec stories 10-11.

## Goal
- Pre-flight 100 serial probes (`src/engine/warp.rs:496-529`).
- `gate_open_ports` unbounded fan-out ~600 (`src/engine/warp.rs:618-633`).
- `SocketCache` random eviction (`src/warp.rs:176-215`).
- Per-probe 10-40ms jitter inside probe (`src/warp.rs:473-474`).

## Scope
- `src/engine/warp.rs`, `src/warp.rs`.
- Parallelize pre-flight cap 8-16 honoring cancel.
- Bound port-gate with scan concurrency (or 64-128).
- LRU/clock eviction for socket cache.
- Move jitter to scheduler/producer.

## Acceptance
- Pre-flight honors cancel; timing test shows parallelism (or in-flight counter test).
- Gate bounded (assert semaphore / max concurrent).
- `cargo test --locked -- warp` green.

## Commands
`cargo test --locked warp`, `cargo clippy --all-targets --locked -- -D warnings`
