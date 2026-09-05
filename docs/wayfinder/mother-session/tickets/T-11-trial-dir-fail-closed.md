# T-11 — trial-dir-fail-closed (F-11) — ASK-FIRST AREA, approved: FAIL CLOSED

## Finding
`fresh_trial_dir` (`src/verify.rs:303-308`) discards `create_dir_all` and
`set_permissions(0o700)` results with `let _`. Downstream failures are
confusing (path to nonexistent dir); worse, credential-bearing trial dirs can
stay world-readable on filesystems where chmod fails.

## Refine decision (approved)
Fail closed: abort the attempt with a clear error.

## Verify
Read `fresh_trial_dir` + callers (`make_trial_dir`, probe path,
`xray::spawn`). Map the signature change blast radius.

## Fix
1. `fresh_trial_dir` → `Result<PathBuf>`; propagate `create_dir_all` errors
   with context (data dir path included).
2. `set_permissions(0o700)` failure → `Err` (fail closed), message names the
   dir + "refusing to stage proxy credentials without owner-only permissions".
3. Update callers (`?` propagation). Check Windows path (no chmod there —
   untouched).

## Test
- Read-only data dir (temp dir with perms stripped, Unix) → attempt fails
  with the clear error, no xray spawn attempted.
- Normal path unchanged (existing lifecycle tests green).

## Files
`src/verify.rs` (+ callers, + tests).

## Gates
`cargo test` + `cargo clippy --all-targets -- -D warnings` + `cargo fmt --check`.
