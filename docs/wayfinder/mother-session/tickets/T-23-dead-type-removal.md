# T-23 — dead-type-removal (F-23) — ASK-FIRST AREA, approved: DELETE

## Gap
9 unused server-era payload types in `src/api/types.rs` since ADR-013:
`ResultsPayload`, `StatusPayload`, `RangesPayload`, `XrayStatusPayload`,
`XrayDownloadResponse`, `RegisterRequest`, `RegisterResponse`,
`ExportConfigRequest`, `ExportConfigResponse`.

## Refine decision (approved)
Delete.

## Verify
Grep each name repo-wide; confirm zero references (tests included).

## Fix
Delete the types (+ now-unused imports). `cargo clippy` is the proof.

## Files
`src/api/types.rs` only.

## Gates
`cargo test` + `cargo clippy --all-targets -- -D warnings` + `cargo fmt --check`.
