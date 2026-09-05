# T-07 — serde-compat-retry (F-07) — ASK-FIRST AREA, approved: tolerant load

## Finding
`src/api/types.rs:167-187`: `WarpConfig.verify_with_wgconf: bool` lacks
`#[serde(default)]` under `deny_unknown_fields` — violates the v0.8.0
invariant and breaks reads of older JSON. Same latent issue on `ScanConfig`
core fields (mode/target/ports/stop/exclude/custom_cidrs/concurrency/
timeout_ms). `deny_unknown_fields` on the persisted retry format makes any
future rename a hard `--retry-last` break.

## Refine decision (approved)
Tolerant `load_config`, strict CLI parsing stays.

## Verify
Read the three config structs + `load_config`. Confirm which fields lack
`#[serde(default)]`.

## Fix
1. Add `#[serde(default)]` to `verify_with_wgconf` and every other
   bool/numeric/Vec/Option field that has a sensible default (do NOT change
   `deny_unknown_fields` on the structs — CLI parsing stays strict).
2. Make `load_config` tolerant: deserialize via an intermediate
   `serde_json::Value`, strip unknown fields (or use a
   `#[serde(default)]`-only shadow struct), then convert. Old files must load;
   new files with extra keys (hand-added) must not hard-fail.
3. Add a version-tolerance test: write a minimal old-shape JSON (missing
   `verify_with_wgconf`, missing newer fields) → loads with defaults.

## Test
- Old-shape JSON loads with defaults (T-07 core).
- Unknown-key JSON loads (tolerance).
- Existing strict CLI-parse tests stay green (no `deny_unknown_fields` change).

## Files
`src/api/types.rs`, `src/retry.rs` (+ tests).

## Gates
`cargo test` + `cargo clippy --all-targets -- -D warnings` + `cargo fmt --check`.
