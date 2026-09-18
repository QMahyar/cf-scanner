# 02: Torn-down verdict (warpscout tail-run detection vs binary Working)

**Type:** grilling (HITL — needs the human; Working is a domain term)

**Blocked by:** none

**Status:** resolved

## Resolution (2026-09-18, human)

- Q1: fail_reason flag — keep Working binary; torn stored as `fail_reason="torn_down"` row, zero contract change.
- Q2: export-only — torn rows appear in csv/json + end-of-scan diagnostic flush; never count toward found/stop, never live Result-as-working, never best/conf/bundles; store `latency_ms: None`.
- Q3: opt-in only — zero-loss stays the WARP verdict rule; torn classifies only when `--warp-probes >= 4`.
- Q4: WARP-probe-only behavior; share `torn_down` wording across phase-2 and wgconf verify errors with no structural change there.

## Question

Do we add warpscout's `torn down` (handshake OK, dies mid-stream: trailing
run ≥3 unanswered + confirm burst, minimum burst 5, never wins best/conf)
as a third endpoint state, or keep `Working` binary and express it another
way (fail_reason? phase2 flag? display-only)?

## Context

- warpscout: `tunnel.go:354-367,457-467` + double-burst `197-207`,
  `working = ok && durable`, torn never wins (`main.go:421-439`).
- Our model (`CONTEXT.md`): Verdict binary, row exists = works; WARP working
  = open + zero probe loss. `fail_reason`, `sent/received/loss_pct` exist.
- Stakes: ternary state touches `api::types`, store sort (`sort_if_dirty`),
  exports, wizard, and the glossary. Cheaper alternative: in-tunnel `/meta`
  single-fetch escalation or phase-2 "connects then stalls" flag.
- Resolve with human: grilling + domain-modeling skills; update glossary/ADR
  only if ternary wins. Feeds ticket 08.

## Answer

### Recommendation: keep `Working` binary; express torn via `fail_reason`, never a third state

Ternary loses on cost/benefit. `fail_reason` (option B) carries the full
signal with zero contract change; display-only (option C) is the fallback
if even stored torn rows are unwanted. Details below; questions for the
human at the end.

### Facts established from the code (not assumed)

- **CDN phase-1 already stores failure rows.** `engine/cdn.rs:362-375`
  builds `latency_ms: None + fail_reason` verdicts and
  `driver.rs:60-77` (`record_and_batch`) pushes them into the store;
  only latency-bearing rows emit live `Result` events and increment
  `found`. Failures flush at end (`engine/mod.rs:344-350`,
  "store-only verdicts (failures, lag-dropped successes)").
- **WARP drops everything lossy silently.** `engine/warp.rs:180`: only
  `latency_ms.filter(|_| failed == 0)` rows are recorded. No
  `fail_reason` rows exist for WARP today. Torn (handshake OK, dies
  later) is a subset of currently-dropped endpoints.
- **Load-bearing invariant: `latency.is_some() ⟺ working`.**
  `record_and_batch`, `working_found` (`mod.rs:228-234`), lazy sort
  (None sorts last), wizard status (`cli_wizard.rs:297`), and
  `diagnostic_line` (`export.rs:27`) all key off it. A ternary row with
  latency + "torn" breaks all five call sites plus NDJSON consumers
  that treat a `Result` event as working.
- **Exports already carry the signal.** csv/json have
  `sent/received/loss_pct/fail_reason` columns; bundles key off
  `phase2.passed` (`export.rs:247`), so torn rows can never leak into
  bundles under any option. Ternary adds export impact exactly zero
  beyond a schema column nobody needs.
- **The durability concept already exists — as a stage, not a state.**
  warpscout's `working = ok && durable` maps onto our two stages:
  handshake probe (ok) + wgconf full-session verify (durable), and
  `warp.rs:297-342` (`finish_full_session`) already fails dies-mid-stream
  with typed errors ("no data reply through tunnel"). Ternary would
  duplicate an existing stage as a new state.
- **Probe-budget killer:** default `probes_per_endpoint = 3`
  (`api/limits.rs:15`). Warpscout torn needs trailing run ≥3 unanswered
  *after* handshake-OK plus a confirm burst ≥5 — unobservable under the
  default budget (needs ≥4 probes minimum, ≥8 for the full algorithm).
  Ternary-by-default either slows every scan ~3x on the
  best-looking endpoints (perverse cost concentration) or only works
  with raised `--warp-probes`, i.e. it is really an opt-in durability
  stage wearing a verdict costume.

### Edge scenarios stress-tested

1. **WARP zero-loss vs torn burst:** endpoint answers 2/3 probes, then
   dies. Today: dropped, identical to never-open. Under B: stored row
   `fail_reason="torn_down"`, `loss_pct` set, excluded from
   `found`/stop-count/best. Working keeps meaning zero loss; no
   glossary change beyond documenting the reason string.
2. **Phase-2 connects-then-stalls:** already `passed: false + error`
   (`Phase2Verdict.error`). No gap, no change needed in any option.
3. **Sort/export:** under B, torn rows sort with failures (latency
   None) or by measured latency if kept — decision needed (see Q2).
   Bundles unaffected in all options.
4. **wgconf-verify death:** already surfaced as a verify error, not a
   verdict. Unifying its wording with the probe-stage `fail_reason`
   (Q4) is the only change worth making there.

### Cost table

| Option | Contract | Store/sort/counting | Glossary/ADR | Probe cost |
|---|---|---|---|---|
| A ternary | new field, `#[serde(default)]`, nested `deny_unknown_fields` | 5+ call sites re-keyed | glossary rewrite + ADR | ~3x on good endpoints |
| B `fail_reason` | none (fields + columns exist) | WARP stores a new row kind; counting guards needed | document reason string | only when probes raised |
| C display-only | none | none | none | none |

### QUESTIONS FOR USER

❓ **Q1** - **Ternary vs flag vs display-only**: Do we (A) add `torn down`
as a third endpoint state in `api::types` (new field, glossary rewrite,
ADR, ~5 call sites re-keyed off the `latency.is_some() ⟺ working`
invariant, ~3x probe cost on good-looking endpoints); (B) keep `Working`
binary and express torn as a `fail_reason` value (e.g. `"torn_down"`) on
a stored row — zero contract change, csv/json columns and
`diagnostic_line` already render it; or (C) display-only — surface the
signal in human-readable lines from existing `sent/received/loss_pct`
with no stored rows and no behavior change?

➡️ Recommended: **B**. It carries the full signal with none of the
contract/domain churn, and bundles are safe in every option (they key
off `phase2.passed`).

---

❓ **Q2** - **If torn rows are stored, what counts?**: Do stored torn rows
(a) increment `found` / satisfy stop conditions, (b) emit live `Result`
events and print as working results, (c) appear in csv/json exports —
and are they (d) eligible for best/conf selection and bundle export?

➡️ Recommended: **only (c), plus end-of-scan diagnostic flush like other
failures**. Never (a), (b-as-working), or (d) — warpscout itself never
lets torn win best/conf, and counting them toward `found` would stop
scans early on dead endpoints. Store with `latency_ms: None` so they
sort with failures and trip none of the `latency.is_some()` working
paths.

---

❓ **Q3** - **WARP zero-loss interaction**: `Working` for WARP today means
open + zero probe loss, and the full torn algorithm (trailing run ≥3 +
confirm burst ≥5) is unobservable at the default `probes_per_endpoint =
3`. Do we (a) keep zero-loss as the `Working` rule untouched and only
classify torn when the user raises `--warp-probes` enough to observe it
(≥4 minimum); or (b) raise the default probe budget so torn detection is
always on?

➡️ Recommended: **(a)**. Zero-loss stays the verdict rule; torn is a
diagnostic subset of currently-dropped endpoints, active only when the
probe budget can observe it. (b) taxes every scan ~3x on exactly the
endpoints that looked good.

---

❓ **Q4** - **Scope**: Is this WARP-probe-only, or do we unify wording
with the two places that already report dies-mid-stream — phase-2
`passed: false + error` ("connects then stalls") and wgconf
full-session verify errors ("no data reply through tunnel")?

➡️ Recommended: **WARP-probe-only for behavior; unify the human-readable
wording** (e.g. share the `"torn_down"`/similar string) across all three
so users see one concept, with zero structural change to phase-2 or
wgconf paths.
