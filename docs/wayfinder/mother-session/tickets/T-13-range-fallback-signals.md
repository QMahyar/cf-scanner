# T-13 — range-fallback-signals (F-13) — ASK-FIRST AREA, approved: WARN + BUNDLED

## Finding
`src/ranges/pool.rs:161-207`: `base_pool`/`base_pool_v6` discard refresh parse
errors via `.ok()`; `effective_pool` swallows I/O + path errors. Corrupt
refresh file = silent bundled fallback, zero signal. (2026 review wanted loud
fail; current code went fully silent. Neither is right.)

## Refine decision (approved)
Warn + bundled: exact parse error to stderr, continue on bundled.

## Verify
Read `base_pool`, `base_pool_v6`, `effective_pool`. Confirm all four swallow
points.

## Fix
1. Return the parse/I/O error with context up to the caller.
2. Caller (engine start + `ranges refresh` status path) emits:
   `tracing::warn!` + one stderr line: `warning: refreshed ranges unusable
   (<path>: <parse error>); using bundled ranges`.
3. Keep availability (never fail the scan for this).

## Test
- Corrupt refresh file in temp data dir → scan proceeds on bundled +
  warning captured (stderr/tracing capture in test).
- Valid refresh still preferred (existing tests).

## Files
`src/ranges/pool.rs` (+ callers, + tests).

## Gates
`cargo test` + `cargo clippy --all-targets -- -D warnings` + `cargo fmt --check`.
