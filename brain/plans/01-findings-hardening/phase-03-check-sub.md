# Phase 03 — check-sub: real probes, cap, row contract

Back to [[plans/01-findings-hardening/overview]]

## Goal
`check-sub` must actually validate subscription entries — probe through the config, cap hostile inputs, emit a usable row contract.

## Findings addressed
- **F3 (high)**: `check_one` builds `ProbeRequest` with `probe_urls: &[]` (check_sub.rs:86). Consequence: xray-routed rows "pass" with zero real probes (spawn-to-bind latency only); inline-routed rows return `all_ok = !targets.is_empty()` = **false** without opening a tunnel. An all-inline subscription reports nothing verified.
- **F5 (medium)**: no cap on parsed spec count (check_sub.rs:44-48) while the engine caps subscriptions at `MAX_SUBSCRIPTION_SPECS = 2048` (api/limits.rs:54, enforced in engine/phase2.rs:308). Effectively unbounded serial probe time on hostile subscriptions.
- **F21 (low)**: `CheckRow.config_index` is `usize::MAX` for every real row and omitted from CLI NDJSON output (main.rs:151-157) — contract field that carries no information.

## Changes
- `src/check_sub.rs`: build probe URLs once (`DEFAULT_PROBE_URL`, matching `Phase2Config::default().effective_probe_urls()`) and pass to every `ProbeRequest`. Enforce `MAX_SUBSCRIPTION_SPECS` after `parse_subscription` (bail in engine's message style, or truncate with a `<truncated>` row reporting the cut).
- `src/main.rs`: enumerate real rows with their config index and include `config_index` in the emitted NDJSON (aggregate/unparseable rows document their sentinel value).
- Update check_sub tests: assert `probe_urls` non-empty (a recording fake), row indices present.

## Data structures
`CheckRow.config_index` becomes meaningful (index into parsed specs; sentinel documented for aggregate rows).

## Verification
### Static
- fmt / clippy `-D warnings` / full test suite GREEN.
### Runtime
- New tests (must FAIL before, PASS after):
  1. probe fake records URLs — every routed config is probed with ≥1 real URL; inline-routed config opens the tunnel (fake InlineTunnelProbe sees a target).
  2. 2049-spec subscription → capped with a clear error/truncation row.
  3. NDJSON rows carry `config_index` mapping back to subscription lines.
- Manual: `cargo run -- check-sub --help` unchanged; behavior change documented in `docs/` if the command's semantics section exists (check `docs/spec.md` for check-sub contract lines).
