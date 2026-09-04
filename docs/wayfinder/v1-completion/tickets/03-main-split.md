## Question

How do we split the 1866-line `src/main.rs` god module into focused modules
without changing CLI behavior?

## Scope

`main.rs` currently contains:
- `Cli` / `ScanArgs` clap types (~150 fields, ~400 lines)
- ~10 `From` impls for arg-enum mapping (~200 lines)
- `build_scan_config` (~120 lines of sequential validation)
- `build_phase2` (~50 lines)
- `run` / `run_scan` orchestration (~200 lines)
- `write_export` / `run_export_config` (~150 lines)
- Test module (~270 lines, 27+ tests)

## Proposed split

- `src/cli.rs` — `Cli`, `ScanArgs`, clap types, `From` impls
- `src/cli/scan_args.rs` — `build_scan_config`, `build_phase2`, validators
- `src/main.rs` — thin async entry: parse → build → run → export
- Export helpers (`write_export`, `export_format_name`) → `src/export.rs`

Also refactor `build_scan_config` (~120 lines of if-else) into smaller
validators: `validate_mode_flags()`, `validate_phase2_flags()`,
`validate_warp_flags()`. Keep CLI-specific flag-conflict checks in CLI layer
(for user-friendly flag names); delegate semantic checks to `validate()`.

## Acceptance

- [ ] All existing tests pass unchanged (moved, not rewritten)
- [ ] `cargo run -- scan --help` output identical
- [ ] No file exceeds 800 lines after split
- [ ] Public API surface unchanged (`src/lib.rs` facade)
- [ ] `cargo test` + `cargo clippy --all-targets -- -D warnings` +
      `cargo fmt --check` all pass

## Boundaries

- Pure refactor — zero behavior change
- Don't touch `ScanConfig::validate()` in this ticket (separate concern)
- API contract changes = ask first
