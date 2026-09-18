# 11: Phase-2 tier fallback ladder

**What to build:** verification survives partially-filtered networks: when the user's probe URLs yield zero passes through the tunnel, verification automatically retries against the next tier (public trace + data-path) and stops at the first tier with a pass — instead of failing the endpoint outright.

**Blocked by:** None (can start immediately).

**Status:** done

Spec: `../spec-best-in-class.md` §P1-2. Inherits spec §6 execution rules.

- [ ] Engine-level tier list `[user probe_urls] → [public trace + data-path]`; advance only on zero-pass tiers; single-tier configs behave exactly as today
- [ ] Tunnel-probe seam stays single-shot (injectable/offline tests keep working); cost bounded by existing cap/stop/dedup + cancel races
- [ ] Any new tier knobs are additive-optional with defaults under `deny_unknown_fields`
- [ ] Tests: zero-pass advances, first-pass stops, single-tier identical; `cargo test` + clippy `-D warnings` + fmt green

## Result

Done 2026-09-18. Engine-only ladder in `src/engine/phase2.rs`; no new
config surface (fixed fallback tier), so `src/api/types.rs` is untouched and
the `deny_unknown_fields` checkbox is vacuously satisfied.

What changed (only `src/engine/phase2.rs`):
- `FALLBACK_TIER_PROBE_URLS`: fixed tier
  `["https://cloudflare.com/cdn-cgi/trace", "https://www.cloudflare.com/"]`
  (public trace = edge reachability + colo, same path the phase-1 HTTP probe
  uses; data-path page = payload delivery. Both return HTTP 200, which is
  what both tunnel probes require; `TunnelProbe` in `src/verify.rs` and
  `src/inline_verify.rs` untouched, still single-shot).
- `phase2_tiers()`: `[user effective URLs] → [fallback]`, deduped to one
  tier on exact ordered match (order decides colo capture, so only exact
  order dedupes).
- `verify_phase` runs one worker wave per tier, sequentially: tier 2 starts
  only when tier 1 yields zero *kept* passes; any kept pass stops the
  ladder. Shared across tiers: `attempts` (cap), `passed` (stop/dedup),
  `first_error`, cumulative `completed`/`errored`; per tier: cursor,
  milestones, terminal flag, tier-relative progress (`done` reported per
  wave via a base offset). Every probe keeps the `select!` +
  `cancelled()` race; cancel/cap checks run between tiers. Tier-2
  candidates recompute from the live store, so tier-1 colo removals are
  skipped, not re-probed. Fail→pass upgrades flow through the existing
  `update_verdict_phase2` guard (pass never downgrades). No URLs, configs,
  or keys in logs (one tier-index-only `tracing::debug` on advance).
- Tests (mock `TunnelProbe` only, no network): new `pass_tier`/`hang_tier`
  mock gates plus 6 tests — zero-pass advances (incl. verdict upgrade),
  first-pass stops (1 probe), fallback-config single-tier (1 probe),
  cancel-during-tier-2 (cancelled summary, 2 attempts), colo-rejected
  tier-1 skips removed rows, `phase2_tiers` dedupe unit test. Two existing
  zero-pass tests (`colo_filter_drops…`, `terminal_progress_emitted_once`)
  pinned to single-tier via fallback URLs so their exact assertions still
  pin today's behavior; no test deleted.

Gate evidence:
- `cargo test`: GREEN — 688 lib + 61 + 16 + 16 + 2 integration, 0 failed
  (39/39 in `engine::phase2`, incl. all pre-existing tests).
- `cargo clippy --all-targets -- -D warnings`: RED repo-wide, but every
  failure is in parallel tickets' uncommitted in-flight code, never this
  file — run 1: `src/warp.rs:445` `too_many_arguments` (P0-5 junk work,
  fixed by its owner mid-session); runs 2–3: `src/engine/speed.rs:181`
  `manual_clamp` (P1-5 burst work, still open). Zero findings mention
  `phase2` in any run. Not touched per ask-first/parallel scope rules.
- `cargo fmt` / `--check`: `src/engine/phase2.rs` standalone
  `rustfmt --check` clean; repo-wide `--check` reports diffs only in
  `src/warp.rs` (parallel ticket, same reason as above).
