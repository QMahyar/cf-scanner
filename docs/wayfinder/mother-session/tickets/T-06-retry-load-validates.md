# T-06 — retry-load-validates (F-06)

## Finding
`load_config` (`src/retry.rs:30-35`) deserializes `last-scan.json` without
calling `cfg.validate()`. Hand-edited/corrupt-but-well-typed JSON
(concurrency=0, timeout_ms=5, mode/config mismatch) goes straight to
`ScanController`.

## Verify
Read `src/retry.rs` + `ScanConfig::validate()`. Confirm no validation call.

## Fix
Call `cfg.validate()` after deserialization; map the error to
"saved scan config is invalid ({}: {e}) — re-run the scan" with the path.
Keep the existing corrupt-JSON error arm.

## Test
- Valid file loads (existing behavior).
- File with `concurrency: 0` (valid JSON, invalid config) → clear invalid
  error, not a downstream engine panic/misbehavior.

## Files
`src/retry.rs` (+ tests).

## Gates
`cargo test` + `cargo clippy --all-targets -- -D warnings` + `cargo fmt --check`.
