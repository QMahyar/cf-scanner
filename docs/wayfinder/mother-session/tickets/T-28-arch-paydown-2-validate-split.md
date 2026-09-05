# T-28 — arch-paydown-2: split validate() (F-27.2)

## Gap
`ScanConfig::validate()` is a ~100-line monolith mixing 6+ concerns
(mode gating, ports, stop, ranges, phase2, warp, filters).

## Fix
Extract per-area fns (`validate_mode_gates`, `validate_ports_split`,
`validate_stop`, `validate_ranges`, `validate_phase2ref`, `validate_warpref`,
`validate_filters`) — thin orchestrator keeps the exact same error order and
variants (error precedence is user-visible via first-error; do NOT reorder).
T-15's new rejections land first (T-15 before T-28), so the split carries them.

## Rules
No error-variant/message changes; tests pin current messages — suite must be
green unmodified (plus T-15's new tests).

## Files
`src/api/validate.rs` (+ tests only if T-15 left gaps).

## Gates
`cargo test` + `cargo clippy --all-targets -- -D warnings` + `cargo fmt --check`.
