# Phase 09 — Cleanup: engine surface

Back to [[plans/01-findings-hardening/overview]]

## Goal
Release build stops carrying test-only API; unused constants get enforced or deleted.

## Findings addressed
- **F17 (medium)**: test-only ScanController API compiled into the release lib (`with_probes`, `run`, `run_reserved`, `summary` — zero production callers; every caller is in tests).
- **F20 (low)**: `MAX_LICENSE_BYTES` (api/limits.rs:45) declared + re-exported, zero references — license length never enforced.

## Changes
- `src/engine/mod.rs`: gate the test-only constructors behind `#[cfg(any(test, feature = "test-helpers"))]` (the `test-helpers` feature already exists in Cargo.toml; integration tests use it if needed — verify `tests/` compile with the feature enabled, else adjust).
- `src/api/limits.rs` + re-export site: delete `MAX_LICENSE_BYTES` (nothing licenses-checks today; re-add with enforcement when a license feature actually exists — subtract-before-you-add).

## Data structures
None. Public-surface reduction only (lib is the only consumer boundary; npm/CI unaffected — verify with grep before deleting).

## Verification
### Static
- fmt / clippy `-D warnings` / full test suite GREEN (both `cargo test` and `cargo test --features test-helpers`).
### Runtime
- No behavior change: full test suite passes; `cargo build --release` succeeds (surface shrunk).
