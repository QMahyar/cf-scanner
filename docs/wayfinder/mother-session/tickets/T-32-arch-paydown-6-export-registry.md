# T-32 — arch-paydown-6: export registry (F-27.6)

## Gap
Adding an export format touches 4 locations (enum, dispatch, help, docs).

## Fix
Registry pattern: one `FORMATS` table mapping name → renderer fn + description;
`ExportFormatArg`, dispatch, `--help` text, and README all derive from it, so
T-24-style additions are one-spot changes. Do AFTER T-24 (registry carries the
new formats). Behavior byte-identical for all existing formats (goldens prove it).

## Files
`src/export.rs`, `src/cli.rs` (help derivation).

## Gates
`cargo test` + `cargo clippy --all-targets -- -D warnings` + `cargo fmt --check`.
