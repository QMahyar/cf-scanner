# 07: Opt-in adaptive pre-flight for WARP

**What to build:** on a network of unknown quality, one flag tunes the probe budget before the scan: a bounded 100-sample handshake pre-flight (aborted cleanly on Ctrl+C, recording nothing) recommends and applies a higher probe count on lossy/high-latency networks, prints what it measured and a reusable re-run command, and yields to any explicit probe setting.

**Blocked by:** None (can start immediately).

**Status:** done

Spec: `../spec-best-in-class.md` §P0-7(a). Inherits spec §6 execution rules.

- [x] `scan --mode warp --adaptive-retries` only (never default-on); exactly 100 samples over the bundled pool plan, each bounded by the configured timeout; zero verdicts recorded
- [x] Ladder per spec (loss/p50/jitter thresholds → 5/7, never above max 10, never lowering an explicit `--warp-probes`, with a stderr note when skipped)
- [x] stdout NDJSON shape unchanged; all human output on stderr including the reusable re-run line
- [x] Tests with injected transports (lossy → bumped, clean → default, explicit-wins); stop/cancel checked every step
- [x] `cargo test` + `cargo clippy --all-targets -- -D warnings` + `cargo fmt --check` green

## Result

**Flag (new, `--mode warp`-only, `WARP` help heading):**
- `--adaptive-retries` → `ScanConfig.adaptive_retries: bool` (flat root, plain
  `#[serde(default)]`, default false; root stays non-strict). CDN mode rejects
  it by explicit flag name; `--retry-last` honors it as an override and applies
  the same explicit-wins rule. Explicit `--warp-probes` always wins: the CLI
  switches the pre-flight off with a stderr note and the engine never sees the
  combination (so the engine can never lower a user-chosen budget).

**Files changed (mine):** `src/api/types.rs` (1 root field + `Default`),
`src/cli.rs` (flag, placed after ticket 05's `--warp-junk-*` block, untouched),
`src/cli/scan_args.rs` (CDN gating, explicit-wins skip + `adaptive_skip_note`
helper, retry-last override, wiring), `src/cli/scan_args/tests.rs` (`args()`
field + 5 tests), `src/engine/warp.rs` (pre-flight helper + 13 tests),
`README.md` (1 flag row — required by the
`every_long_scan_flag_is_documented_in_help_and_readme` gate).
`rust-engineering`/`rust-async` skills unavailable in this session; proceeded
strictly per spec §6 + AGENTS.md v0.8.0 invariants. No new dependencies.

**Behavior:**
- `run_warp` runs `warp_preflight` after transport construction (reuses the
  built transport, hence ShapeOnly discovery semantics, per-controller
  `SocketCache`, junk profile) and before `clear_store`/planning. Exactly 100
  single probes over `preflight_targets` (bundled pool + same exclusion path,
  `Count(100)` plan on a domain-separated seed, one rotating port per distinct
  host), each passed `timeout_ms`, zero verdicts.
- Ladder (`adaptive_recommendation`, pure): loss>25% or jitter(p90−p50)>1500 →
  7; else loss>10% or p50>800 → 5; else default 3. Applied as
  `ladder.max(current).min(10)` — never lowers (retry-last lineage included),
  never above max 10. Strictly-greater edges pinned by test.
- Cancel (`select!` + `cancelled_signal` race per probe, latch checked every
  step; found/cap cannot fire pre-scan with zero scanned/found — noted in
  code): abort returns `None`, `run_warp` short-circuits to
  `finish(started, 0, 0)` (cancelled, nothing recorded, main loop never runs).
- stderr only: `PreflightReport::stderr_lines()` →
  `warp pre-flight: 100 samples, loss 30%, p50 120ms, p90 200ms, jitter 80ms → probes 3 → 7`
  (or `→ probes 3 (unchanged)` / `0 samples (pool fully excluded)` variant) +
  `re-run: cf-scanner scan --mode warp --warp-probes 7`. stdout NDJSON path
  (`run_scan` streaming) untouched.
- E2E proof: lossy pre-flight (100% loss → 7) turns a 1-answer-then-death
  endpoint into a `torn_down` row with `sent == 7` — unreachable at the default
  budget of 3 (dormant path, existing test).

**Gate evidence:** `cargo test` all green (710 lib incl. 13 new engine + 5 new
CLI tests, 66 bin, 16 + 16 + 2 integration, 0 failed). `cargo clippy
--all-targets -- -D warnings` clean (one self-caused `manual_div_ceil` fixed
via `div_ceil`; the ticket-05-era `speed.rs` pre-existing failure is gone —
parallel tickets resolved it, verified green on the full tree).
`cargo fmt --check` clean (fmt applied to my hunks only; parallel tickets'
files byte-identical per `git diff --numstat` scoping).
