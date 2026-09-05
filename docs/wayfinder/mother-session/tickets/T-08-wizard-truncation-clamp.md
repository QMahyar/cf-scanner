# T-08 — wizard-truncation-clamp (F-08)

## Finding
`src/cli_wizard.rs:23`: `u32::try_from(host_count).unwrap_or(MAX_SCAN_COUNT)`
substitutes exactly 100,000 for huge pools instead of clamping — a pool with
billions of hosts is treated as exactly MAX_SCAN_COUNT.

## Verify
Read the line + `MAX_SCAN_COUNT` definition + `host_count()` return type.

## Fix
`.unwrap_or(u32::MAX).min(MAX_SCAN_COUNT)` (saturating cast + cap). One line.

## Test
Unit test: host_count > u32::MAX → result == MAX_SCAN_COUNT (not silent 100k
coincidence — use a MAX_SCAN_COUNT-independent assertion, e.g. value is capped
not substituted; if MAX_SCAN_COUNT == 100_000 the test pins the clamp path via
a u128 > u32::MAX input).

## Files
`src/cli_wizard.rs` (+ test).

## Gates
`cargo test` + `cargo clippy --all-targets -- -D warnings` + `cargo fmt --check`.
