# T-16 — validation-serde-tests (F-16)

## Gaps (`src/api/types_tests.rs`)
1. 10 validation rules with ZERO tests: Phase2OnlyNeedsConfigs,
   Phase2OnlyWrongMode, WarpPresetNotAllowed, WarpCidrsNotAllowed,
   InvalidPhase2Concurrency, ConfigEntryTooLong, SniTooLong, WgconfTooLong,
   TooManyEndpoints (+ confirm full list against `ConfigError` variants —
   every variant needs ≥1 trigger test).
2. Boundary ACCEPT cases never tested: concurrency 1/1000, timeout_ms
   100/30000, probes_per_endpoint 1/10, HTTP codes 100/599, ports 64,
   stop values at caps.
3. No serde round-trips: `ScanEvent::Phase2Progress`, `ScanEvent::Failed`,
   full `Verdict` (all fields), `WarpConfig`, full `Phase2Config`.

## Fix
Table-driven tests: one `#[test]` per error variant (trigger + message
snapshot optional); boundary accept/reject pairs; round-trip fns for the
missing types. Pure test ticket — no production code change expected (if a
test exposes a real validation hole, file it as a T-15 follow-up, don't
scope-creep).

## Files
`src/api/types_tests.rs` only (+ helpers if needed).

## Gates
`cargo test` + `cargo clippy --all-targets -- -D warnings` + `cargo fmt --check`.
