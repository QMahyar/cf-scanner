# Phase 05 — I/O safety: capped reads + trial-dir guard

Back to [[plans/01-findings-hardening/overview]]

## Goal
Untrusted-sized inputs get capped; credential-bearing temp state cannot leak on error paths.

## Findings addressed
- **F11 (medium)**: phase-2 config *file* entries read with uncapped `std::fs::read_to_string` in `spawn_blocking` (phase2.rs:293-299) — no size cap, no cancel check during read; a multi-GB/special file hangs or OOMs the scan. Every comparable path caps (MAX_WGCONF_BYTES=64KiB, MAX_CONFIG_ENTRY_BYTES=8KiB, 64MiB HTTP caps).
- **F7 (medium)**: `open_tunnel_session` (verify.rs:76-114) creates the trial dir, then has fallible `?` steps (`ensure_binary`, `spawn_with_retry` — which already wrote a credential-bearing config.json) BEFORE `TrialDirGuard` is constructed at line 114 → dir with UUID/password leaks on failure, persists under the data dir until a later scan's hourly sweep.

## Changes
- `src/engine/phase2.rs`: cap the config file read via `File::take(MAX_WGCONF_BYTES + 1)` + `read_to_string`, bail when over-cap (mirror `load_wgconf_file` in cli/scan_args.rs).
- `src/verify.rs`: construct `TrialDirGuard` immediately after `make_trial_dir`, move (not re-create) it into `TunnelSession { _guard }` so every `?` early return cleans up.

## Data structures
None new. `TrialDirGuard` ownership moves earlier in one function.

## Verification
### Static
- fmt / clippy `-D warnings` / full test suite GREEN.
### Runtime
- New tests (must FAIL before, PASS after):
  1. phase2: config file larger than the cap → clear error, no hang (use a temp file > cap).
  2. verify.rs: fake opener/spawn failing after config write → no `trial-*` dir left under the data dir.
- Manual: none beyond tests (paths are error paths).
