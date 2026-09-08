# T-30 — arch-paydown-4: controller groups (F-27.4)

## Gap
`ScanController` is a god object (13 fields, ~1,100 lines in mod.rs).

## Fix
Extract cohesive field groups into sub-structs owned by the controller
(candidates: phase-2 handle state → `Phase2Handle`, speed-test handle →
`SpeedHandle`, warp socket cache stays per-controller but moves behind an
accessor, counters → `ProgressCounters`). Controller keeps the same public API;
no logic change. Mechanical field-move commits.

## Rules
Public API unchanged; suite green unmodified. ≤5 files per commit.

## Files
`src/engine/mod.rs` (+ new small modules if warranted).

## Gates
`cargo test` + `cargo clippy --all-targets -- -D warnings` + `cargo fmt --check`.
