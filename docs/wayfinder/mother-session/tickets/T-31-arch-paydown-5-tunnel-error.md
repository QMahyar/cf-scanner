# T-31 — arch-paydown-5: tunnel/error recon (F-27.5)

## Gaps
1. `TunnelProbe` vs `TunnelOpener` overlap (two abstractions, one job).
2. `WarpRegisterError::detail` never surfaced in output.
3. `WizardInterrupted` error matching is fragile (stringly matching? verify).

## Fix
1. Reconcile: keep both traits ONLY if each has ≥2 distinct implementors with
   distinct semantics; otherwise merge into one trait with a defaulted method.
   Document the survivor's contract. Behavior unchanged.
2. Surface `detail` in the warp-register failure message (human + NDJSON error
   path), redacted as today (no keys — verify redaction holds).
3. Replace fragile matching with a typed signal (error variant or explicit
   sentinel), keeping UX identical.

## Files
`src/verify.rs`, `src/warpgen.rs`, `src/cli_wizard.rs`, `src/api/error.rs`.

## Gates
`cargo test` + `cargo clippy --all-targets -- -D warnings` + `cargo fmt --check`.
