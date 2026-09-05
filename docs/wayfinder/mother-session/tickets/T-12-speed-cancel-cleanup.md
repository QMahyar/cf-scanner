# T-12 — speed-cancel-cleanup (F-12)

## Finding
`src/engine/speed.rs:183-198`: on cancel winning the `select!` mid-download,
cleanup of `OpenedTunnel` (`src/verify.rs:128-136`, no `Drop` impl — cleanup
is a boxed future in a dropped struct) is implicit. xray child / trial dir
may leak on cancel.

## Verify
Read `OpenedTunnel` + its cleanup field + `measure_through_tunnel` drop points.
Confirm no `Drop` impl and that cancel-drop skips cleanup.

## Fix
Explicit guard: implement `Drop` for `OpenedTunnel` that spawns/blocks the
cleanup deterministically, OR restructure so the cleanup future is awaited on
the cancel path (prefer explicit: a small `TunnelGuard` whose `Drop` kills +
sweeps synchronously where possible, async cleanup via `tokio::spawn` fireaway
with best-effort + startup sweep as backstop — startup sweep already exists
per v0.8.0 notes; confirm and cite).

## Test
Regression: FakeOpener + cancel mid-download → assert tunnel `close()` called
(count via fake) and no trial dir left behind (temp-dir assertion).

## Files
`src/verify.rs`, `src/engine/speed.rs` (+ tests).

## Gates
`cargo test` + `cargo clippy --all-targets -- -D warnings` + `cargo fmt --check`.
