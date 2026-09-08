# T-09 — phase2-only-flag (F-09) — ASK-FIRST AREA, approved: REMOVE

## Finding
`--phase2-only` exists in `--help` (`src/cli.rs:224`), the engine handles it
(`src/engine/cdn.rs:115-121`), but `validate_phase2_flags`
(`src/cli/scan_args.rs:195-198`) unconditionally rejects it — no user flag
combination can succeed; the wizard never sets it.

## Refine decision (approved)
Remove the flag + the now-unreachable engine path.

## Verify
Confirm: grep `phase2_only` across repo; list every reference (cli.rs,
scan_args.rs, cdn.rs, tests, docs).

## Fix
1. Remove `--phase2-only` from `ScanArgs` (+ help text).
2. Remove the `validate_phase2_flags` rejection arm.
3. Remove the `cfg.phase2_only` engine branch (or keep the struct field?
   NO — remove field too; `deny_unknown_fields` means a cleaner break now
   than later. Check `Phase2Config` vs `ScanConfig.phase2_only` placement
   first).
4. Update README/AGENTS if the flag is mentioned; update `--help` golden
   tests if any.

## Test
- `cargo test` green (removal proof).
- Help-output test (if exists) updated; assert flag absent.

## Files
`src/cli.rs`, `src/cli/scan_args.rs`, `src/engine/cdn.rs`, `src/api/types.rs`
(if field lives there), docs.

## Gates
`cargo test` + `cargo clippy --all-targets -- -D warnings` + `cargo fmt --check`.
