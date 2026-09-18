# 03: Auto-tune UX (adaptive pre-test + find-junk/find-sni + budget-split)

**Type:** grilling (HITL — CLI surface + defaults)

**Blocked by:** none

**Status:** resolved

## Resolution (2026-09-18, human)

- Q1: opt-in `--adaptive-retries` flag for WARP pre-flight (100 samples, 3→5→7 ladder, explicit `--warp-probes` wins).
- Q2: `tune` subcommand (`tune fragment` / `tune junk` / `tune sni`), not scan flags.
- Q3: adopt blocked-vs-slow framing (wizard question + `--network-profile` + fragment prompt reword; raw knobs authoritative).
- Q4: budget-split TCP/TLS always-on, no flag (ceiling unchanged).

## Question

What auto-tuning does the CLI get: BPB's 100-sample pre-flight that bumps
retries (3→5→7 on latency/loss/jitter thresholds, `network.go:71-194`),
warpscout's `find-junk`/`find-sni` threshold rescan loops printing reusable
commands, SenPai's budget-split probe timeout (TCP ≤¼, TLS ≤½), and the
"blocked vs slow" one-question noise toggle — and how does a future
`find-fragment` tuner for our light/medium/heavy presets fit?

## Context

- Candidates: opt-in `--adaptive-retries`, `find-fragment` subcommand,
  budget-split in `probe.rs`, blocked-vs-slow framing for `--fragment`.
- Constraints: defaults must not change silently; every loop checks stop/
  cancel; no unbounded pre-test cost; wizard stays thin over the engine.
- Resolve with human over a CLI sketch (flags, thresholds, output lines).
  Feeds ticket 08.

## Answer

Sketch only — no code landed, no defaults changed. All tuning is opt-in;
every loop checks stop/cancel (`select!` + `ProbeContext::cancelled()`,
per AGENTS.md); wizard only maps answers onto existing `ScanConfig`
fields and shows them in `config_recap`.

### 1. Pre-flight adaptive retries (BPB analogue, WARP-only)

- Flag: `scan --mode warp --adaptive-retries` (opt-in). Engine-side
  helper on `ScanController`; CLI passes one bool. `ScanConfig` gains
  `#[serde(default)] pub adaptive_retries: bool` (flat root field —
  no `deny_unknown_fields` issue, forward-compat preserved).
- Cost: exactly 100 handshake probes against the bundled pool plan
  (seed-derived, same sampler as the scan), each bounded by
  `--timeout-ms`; Ctrl+C aborts mid-flight, zero verdicts recorded.
- Ladder (from the 100 samples; `loss` = no-response rate, `jitter` =
  p90−p50 handshake ms):
  - default `--warp-probes 3` stays unless: `loss > 10%` or `p50 > 800`
    → 5; `loss > 25%` or `jitter > 1500` → 7. Never exceeds the
    existing max 10; never lowers an explicit `--warp-probes` (explicit
    wins, pre-flight skipped with a stderr note).
- Output (stderr, human-only; stdout NDJSON unchanged):
  `adaptive pre-flight: 100 samples, loss 18%, p50 940ms, jitter 620ms → --warp-probes 5`
  plus reusable: `re-run with: cf-scanner scan --mode warp --warp-probes 5 --count 512`.
- Recommendation: opt-in flag, NOT default-on (bounded but non-zero
  cost; silent default change banned by ticket constraints).

### 2. find-junk / find-sni threshold loops (warpscout analogue)

- Gating: engine currently has NO WARP junk/SNI knobs (`WarpConfig` =
  endpoints/probes/wgconf only). These tuners presuppose ticket 01
  landing such knobs; if it doesn't, this half is dropped, not stubbed.
- Shape if knobs land: subcommand `tune` mirroring the existing
  `ranges`/`warp-config` style —
  `cf-scanner tune junk [--candidates 50 --need-pct 30]` and
  `cf-scanner tune sni [...]`. Each walks a bounded candidate list,
  resampling N endpoints per value, stopping at the first value with
  `open% >= need-pct`; every step checks stop/cancel; total cost =
  `len(candidates) × N × timeout`, printed up front.
- Output: per-step stderr `try junk=64: 12/50 open (24%)…` then
  reusable `use: cf-scanner scan --mode warp --warp-junk 128`.
- Recommendation: `tune` subcommand over `--tune-*` scan flags (keeps
  `scan` surface clean; matches repo subcommand precedent).

### 3. Budget-split timeouts (SenPai analogue)

- `probe.rs:218` already splits HTTP 30/30/rest (`step_budgets` + the
  `stalled_tls_handshake_fails_fast` pin). Proposal: apply the same
  pattern to `TcpTransport`/`TlsTransport` — connect ≤¼ `timeout_ms`,
  TLS ≤½ of the remainder, hard ceiling still `timeout_ms`, stable
  `reason()` strings unchanged.
- Recommendation: always-on, no flag (ceiling and verdicts unchanged;
  only black-holes fail faster — a strict improvement, not a default
  change in outcomes).

### 4. Blocked-vs-slow one-question toggle + fragment framing

- CLI: `--network-profile blocked|slow` (unset = today's defaults).
  Mapping (CDN): blocked → `timeout_ms 5000`, `idle-hold 2000`;
  slow → `timeout_ms 8000`, concurrency halved from input. WARP:
  blocked → probes 5; slow → probes 3, timeout 8000. Explicit flags
  always win over the profile.
- Wizard: one Select after mode — "Is the network fully blocked or
  just slow?" — mapped to the same fields, shown in recap as
  `profile     blocked`. Phase-2 fragment prompt reframed the same
  way: "fully blocked (heavy) or just slow (light)?" with Medium +
  Custom kept as advanced options.
- Recommendation: adopt the framing in wizard text + `--network-profile`
  flag; keep raw knobs authoritative.

### 5. Future find-fragment tuner (light/medium/heavy)

- `cf-scanner tune fragment --config <uri> [--need 3]` (or
  `--tune-fragment` scan flag — see Q2): verifies a small fixed
  candidate subset through xray with light→medium→heavy, stops at the
  first preset verifying `need` endpoints, prints
  `use: cf-scanner scan --phase2-configs <uri> --phase2-fragment medium`.
  Bounded: 3 presets × subset × phase2 timeout; cancel-safe; never
  logs configs/keys.

## QUESTIONS FOR USER

1. (RECOMMENDED: opt-in) Pre-flight: opt-in `--adaptive-retries` flag,
   or default-on for WARP scans?
2. (RECOMMENDED: subcommand) Fragment tuner: `tune fragment`
   subcommand (symmetric with `tune junk`/`tune sni`), or
   `--tune-fragment` scan flag?
3. (RECOMMENDED: adopt) Blocked-vs-slow: adopt the framing (wizard
   question + `--network-profile` + fragment prompt reword), or keep
   current neutral tuning language?
4. (RECOMMENDED: always-on) Budget-split for TCP/TLS: always-on with
   no flag (ceiling unchanged), or gated behind `--budget-split`?
