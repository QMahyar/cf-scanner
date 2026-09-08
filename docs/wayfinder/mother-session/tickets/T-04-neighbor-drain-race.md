# T-04 — neighbor-drain-race (F-04)

## Finding
`src/engine/cdn.rs:218-230`: the final `side_rx` drain breaks when
`inflight == 0`, but a worker can enqueue a neighbor task between its own
decrement and the producer's check — orphaned tasks are never probed/counted.

## Verify
Read the drain loop + `NeighborHub` (`src/engine/neighbor.rs`) + where
`inflight` is inc/dec'd. Confirm the check-then-break interleaving.

## Fix
Drain-then-check: loop `try_recv` until `Empty`, and only break on `Empty`
when `inflight == 0` AND a re-check after a full drain still sees `Empty`
(double-checked drain), or replace with a generation/sequence counter.
Keep it minimal — smallest change that closes the interleaving.

## Test
Regression test with `--neighbor-scan` + scripted fake that always hits:
assert `scanned` equals main + neighborspace count (no silent drops).
A deterministic unit test on the drain logic is acceptable if the full path
is timing-sensitive (prefer deterministic).

## Files
`src/engine/cdn.rs` (+ tests).

## Gates
`cargo test` + `cargo clippy --all-targets -- -D warnings` + `cargo fmt --check`.
