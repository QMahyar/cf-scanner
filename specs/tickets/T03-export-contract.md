# T03 — export stdout purity + bundle fail-fast + registry + LiveExport

Spec stories 5-7, 17-18.

## Goal
- `src/main.rs:261-301` streams NDJSON, then `src/export.rs:768-771` writes blob to same stdout when `--export -`.
- Bundle formats fail only at export time (`src/export.rs:290-302`).
- `bundle_body` catch-all becomes base64 (`src/export.rs:314-325`).
- `LiveExport::push_line` flushes per line (`src/export.rs:887-892`).

## Scope
- `src/export.rs` `write_export`, `render_bundle`, `bundle_body`, `LiveExport`; `src/cli/scan_args.rs` `build_scan_config`; `src/main.rs` export arg validation.
- Reject `--export -` for `scan` with actionable error (keep `--export-live -` rejected).
- Fail fast when format kind is Bundle/Sharelinks and phase2 is None.
- Make format match exhaustive (unknown -> error).
- Buffer LiveExport (BufWriter, flush per batch / finish).

## Acceptance
- New tests: `--export -` rejected; bundle-without-phase2 fails before scan; unknown format errors; LiveExport batches.
- E2E `tests/cli_scan_agent.rs` pattern followed (offline 203.0.113.0/30 + --seed).
- `cargo test --locked`, clippy, fmt green.

## Commands
`cargo test --locked --test cli_scan_agent`, `cargo clippy --all-targets --locked -- -D warnings`
