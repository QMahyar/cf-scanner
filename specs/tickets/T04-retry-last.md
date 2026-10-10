# T04 — retry-last explicit conflicts

Spec story 8.

## Goal
`src/cli/scan_args.rs:13-62` early-returns handling only 4 fields; other flags silently dropped.

## Scope
- `src/cli/scan_args.rs` retry-load path.
- Detect non-default scan flags combined with `--retry-last` (target/cap/count/ports/concurrency/timeout etc.) and warn on stderr (or error with --strict if exists). At minimum warn.
- Ensure `cap_warning` path (`src/cli/scan_args.rs:461-469`) still runs for retry.

## Acceptance
- Test: `--retry-last` + `--target` (or `--concurrency`) emits warning; retry still applies documented override subset.
- `cargo test --locked -- retry` + scan_args tests green.

## Commands
`cargo test --locked retry`, `cargo clippy --all-targets --locked -- -D warnings`
