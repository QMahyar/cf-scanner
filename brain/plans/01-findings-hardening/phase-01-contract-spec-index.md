# Phase 01 — Contract: spec_index + speed-test resolution + unit rename

Back to [[plans/01-findings-hardening/overview]]

## Goal
A passing phase-2 endpoint's speed test must measure *its own* tunnel, and the serialized speed unit must tell the truth.

## Findings addressed
- **F1 (high)**: `speed.rs build_passing_index` does `specs.get(cfg_idx as usize)` where `cfg_idx` is the raw `p2.configs` entry index but `specs` is the expanded vec (subscription entries expand to N specs sharing one idx; skipped entries shift positions). Result: multi-spec subscriptions measure `specs[0]`; skipped-entry scans silently drop endpoints from the speed test.
- **F10 (medium)**: `speed_test_mbps` (api/types.rs) is actually MB/s (`bytes/1024²/s`); contract name contradicts unit by 8×.
- **F16a**: regression test for the speed-test mapping.

## Changes
- `src/api/types.rs`: add `#[serde(default)] pub spec_index: Option<u32>` to `Phase2Verdict` (position within the expanded specs vec; `config_index` stays the raw entry index for exports). Rename `speed_test_mbps` → `speed_test_mb_s` on `Phase2Verdict`.
- `src/engine/phase2.rs`: worker already knows its expanded position `si` — set `spec_index: Some(si as u32)` at both verdict construction sites (~lines 149, 198).
- `src/engine/speed.rs`: `build_passing_index` resolves via `spec_index` (fall back to `config_index` when `None` for parity with the existing None-continue). Rename all `mbps` naming to `mb_s` locally.
- `src/export.rs` + CSV header: rename the `speed_test_mbps` column to `speed_test_mb_s`.
- Any wizard/CLI help already says MB/s — no change needed there (verify).

## Data structures
`Phase2Verdict` gains `spec_index: Option<u32>`; existing `config_index: Option<u32>` semantics unchanged (raw entry index).

## Verification
### Static
- fmt / clippy `-D warnings` / full test suite GREEN.
### Runtime
- New tests (must FAIL before the fix, PASS after):
  1. `speed.rs`: subscription entry expanding to 2+ specs (FakeSub, speed_test=true) with a TunnelOpener that records which spec it received — each passing endpoint's speed test opens its own expanded spec's tunnel.
  2. `speed.rs`: configs = skipped-entry + direct URI with speed_test=true — the pass is still measured (not silently dropped).
  3. Contract/serialization: `speed_test_mb_s` appears in serialized `Phase2Verdict` JSON; CSV header uses the new name.
- Manual: `cargo run -- scan --mode cdn --preset quick --json --speed-test 1 --export - --export-format json` — verdict JSON carries `speed_test_mb_s`.
