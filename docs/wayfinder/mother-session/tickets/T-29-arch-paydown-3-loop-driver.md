# T-29 — arch-paydown-3: probe-loop driver (F-27.3)

## Gap
~200 lines of structural duplication between the CDN and WARP probe loops
(worker spawn, channel dispatch, stop-check plumbing, progress emission).

## Fix
Extract ONE generic driver parameterized by the probe body, WITHOUT
regressing the intentional separations (audit positives: loops are correctly
separate in policy, dispatch model differs phase-1 vs phase-2, worker channels
are per-worker round-robin). Dedupe ONLY the mechanical worker/plumbing part;
policy stays in `cdn.rs`/`warp.rs`.

## Rules
Behavior-preservation: full suite green + targeted review of the diff. If the
generic driver starts leaking policy (mode-specific `if`s multiplying), ABORT
the ticket with evidence — duplication is cheaper than the wrong abstraction.

## Files
`src/engine/cdn.rs`, `src/engine/warp.rs` (+ new `src/engine/driver.rs`).

## Gates
`cargo test` + `cargo clippy --all-targets -- -D warnings` + `cargo fmt --check`.
