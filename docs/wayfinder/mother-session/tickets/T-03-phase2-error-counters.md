# T-03 — phase2-error-counters (F-03)

## Finding
`src/engine/phase2.rs:213-216`: in the `Err` branch, `break` fires BEFORE the
`errored` increment and `first_error` recording when `passed.len() >=
stop_found`. Effect: errored undercounts, `first_error` can stay `None`
despite real errors, `done == total` terminal check skews.

## Verify
Read the `Err` branch; confirm ordering of break vs counter/error capture.

## Fix
Record the error (increment `errored`, set `first_error` if unset) FIRST,
then break. No other behavior change.

## Test
Regression test: stop_found=1, one pass + one error racing → summary shows
`errored >= 1` (deterministic via scripted fake: pass on first IP, error on
second, stop_found=1).

## Files
`src/engine/phase2.rs` (+ tests).

## Gates
`cargo test` + `cargo clippy --all-targets -- -D warnings` + `cargo fmt --check`.
