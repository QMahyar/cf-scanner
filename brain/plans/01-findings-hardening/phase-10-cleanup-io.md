# Phase 10 — Cleanup: I/O layer

Back to [[plans/01-findings-hardening/overview]]

## Goal
Delete dead code; one guarded-write implementation instead of three.

## Findings addressed
- **F18 (low)**: `warpgen::has_identity()` — zero callers anywhere (leftover from removed server/tray).
- **F23 (medium)**: `ranges::fetch_bytes()` (ranges/http.rs:148) — zero production callers (only its own module test), while `xray::RealFetch::bytes` (xray.rs:617) re-implements the same capping/validation guards.
- **F19 (low)**: three hand-rolled guarded-write implementations (`paths::write_secret`, `warpgen::write_private`, `warpgen::write_private_replace`).

## Changes
- Delete `has_identity` (and its test).
- Consolidate `RealFetch::bytes` onto a single capped-fetch implementation (keep `fetch_bytes`' guards, delete the duplicate, or fold `fetch_bytes` into the RealFetch path and update the module test — pick the smaller diff after reading both bodies).
- Route `warpgen::write_private` through `paths::write_secret` (verify permissions/atomicity parity first: warpgen's replace uses OsRng-salted temp + rename; if `paths::write_secret` lacks atomic-replace, extend IT with the salting and have both call it — one implementation, two callers).

## Data structures
None. Pure deletion/consolidation.

## Verification
### Static
- fmt / clippy `-D warnings` / full test suite GREEN; grep proves zero remaining references to deleted items.
### Runtime
- WARP identity generation flow covered by existing warpgen tests (they must pass unchanged — write path behavior identical).
- xray download path covered by existing `ensure_binary` tests.
