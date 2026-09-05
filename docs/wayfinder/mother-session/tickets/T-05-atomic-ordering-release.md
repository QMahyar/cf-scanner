# T-05 — atomic-ordering-release (F-05)

## Finding
`src/engine/cdn.rs:326,328`: `scanned`/`found` use `fetch_add(Relaxed)` while
`ProbeContext::should_stop()` reads with `Acquire`. On weakly-ordered
architectures (AArch64 — a SHIP target: linux-aarch64/Termux) the producer can
read stale values and overshoot cap/found.

## Verify
Grep all `fetch_add`/`store`/`load` on `scanned`/`found`/`errored` in
`src/engine/` (cdn.rs AND warp.rs + phase2.rs counters). List every
write-side ordering.

## Fix
Write side → `Ordering::Release` (free on x86, one barrier on ARM; pairs with
the existing `Acquire` reads). Apply to all stop-condition counters
(`scanned`, `found`, and any `errored`/`completed` used in stop checks).
No logic change.

## Test
Existing overshoot tests must stay green (`cap_overshoot*`, stop tests).
No new test strictly needed (ordering is not directly observable in a unit
test); note rationale in commit message. If cheap, assert stop-check reads use
`Acquire` via code inspection in review.

## Files
`src/engine/cdn.rs`, `src/engine/warp.rs` (+ phase2.rs if same pattern).

## Gates
`cargo test` + `cargo clippy --all-targets -- -D warnings` + `cargo fmt --check`.
