# Phase 07 — Export hardening: temp files + stdout + help

Back to [[plans/01-findings-hardening/overview]]

## Goal
Export writes carrying credentials get exclusive, randomized temp files; stdout export fails loudly instead of panicking; flags tell the truth.

## Findings addressed
- **F13 (low)**: `atomic_write_file` (export.rs:728-748) builds temp names `{file}.tmp-{pid}-{counter}` (predictable) and opens with write+create+truncate, no exclusive flag, no unix mode → world-readable on unix, symlink/pre-create race possible. Bundles carry UUIDs/keys/passwords. (Windows default DACL limits exposure, hence low.)
- **F14 (low)**: stdout export uses `println!` (export.rs:719) — panics on closed pipe instead of failing gracefully.
- **F22 (low)**: `--phase2-custom` help documents `packets,length,interval` but the parser consumes `length,interval` and silently drops a third component (cli/scan_args.rs:240-246).

## Changes
- `src/export.rs`: temp file created with `create_new(true)` (exclusive) and a random salt (mirror `warpgen.rs write_private_replace`'s OsRng salting); unix `.mode(0o600)`; reuse `paths::write_secret`-equivalent permission handling if it composes cleanly (else keep local, consistent with warpgen consolidation decision in phase-10). stdout path: write via `std::io::stdout().write_all` + flush, map errors to `Result`.
- `src/cli.rs` / `src/cli/scan_args.rs`: fix `--phase2-custom` help to `length,interval` and reject values with more than one comma (explicit error, not silent drop).

## Data structures
None.

## Verification
### Static
- fmt / clippy `-D warnings` / full test suite GREEN.
### Runtime
- New tests (must FAIL before, PASS after):
  1. Two concurrent `atomic_write_file` calls to the same dest → both succeed, no clobber/race (exclusive create).
  2. Stdout export with a closed/failing sink → returns Err, no panic (test via a failing writer seam if one exists, else the write-error branch).
  3. `--phase2-custom 1-3,10-20,10-20` → explicit error naming the two-field grammar.
- Manual: `cf-scanner scan ... --export - --export-format json | head -1` no longer panics on SIGPIPE-style closure.
