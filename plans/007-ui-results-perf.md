# Plan 007: Make live results rendering O(1) per verdict instead of O(n) per tick

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md`.
>
> **Drift check (run first)**: `git diff --stat 51c4711..HEAD -- ui/src/lib/store.svelte.ts ui/src/lib/resultsView.svelte.ts ui/src/lib/components/ResultsTable.svelte`
> On mismatch with the excerpts below, STOP.

## Status

- **Priority**: P2
- **Effort**: M
- **Risk**: MED (view semantics must stay byte-identical; mitigated by characterization tests first)
- **Depends on**: plans/001-ui-ci-baseline.md (its `resultsView.test.ts` is the safety net — extend it FIRST)
- **Category**: perf
- **Planned at**: commit `51c4711`, 2026-08-26

## Why this matters

Every arriving SSE verdict currently costs O(n) work on the main thread, twice:
`applyResult` runs `findIndex` with template-string key comparisons over the
whole results array (`store.svelte.ts:54-59`), and the `$derived` view chain
re-filters and re-sorts the entire list per mutation
(`resultsView.svelte.ts:82-99`), with three more full passes in
`ResultsTable.svelte:35-48`. At 10,000 found endpoints that is on the order of
a billion string constructions/compares across a scan — the UI degrades
progressively exactly while the user is watching it. The DOM is capped
(`DEFAULT_RENDER_CAP`); the computation is not.

## Current state

- `ui/src/lib/store.svelte.ts:54-59` — `applyResult` (read the exact function):
  upsert-by-`${ip}:${port}` via `app.results.findIndex(...)`. Called from
  `App.svelte:57` (live SSE) and `App.svelte:29` (hydrate loop).
- `ui/src/lib/resultsView.svelte.ts:82-99` — `matched`, `rows` (spread +
  sort), `picked` are `$derived` off `app.results`; `rows` sorts a COPY every
  recomputation. A stale comment at ~47-48 claims `$state` does not track
  in-place Set mutation (stale for Svelte 5 — do not propagate it).
- `ui/src/lib/components/ResultsTable.svelte:35-48` — `chipRows` filter,
  `passedRows` filter, `tunnelSummary` scan: three full passes per mutation.
- `DEFAULT_RENDER_CAP` bounds DOM rows (find its definition in
  `ResultsTable.svelte` or `resultsView.svelte.ts`).
- Sort semantics to preserve exactly: latency ascending, then ip, then port
  (mirrors the Rust store's `sort_if_dirty` — see `src/engine/mod.rs`
  sort_if_dirty for the canonical order). Filter semantics: chip filter +
  `maxLatency` + search, whatever `resultsView.svelte.ts` implements — read
  it fully before changing anything.

## Commands you will need

| Purpose | Command | Expected |
|---|---|---|
| Typecheck | `cd ui; npm run check` | exit 0 |
| Tests | `cd ui; npm test` | all pass |
| Build | `cd ui; npm run build` | exit 0 |
| Manual soak | serve + run a real scan (or feed synthetic verdicts via a dev-only harness) | UI stays responsive at 10k rows |

## Scope

**In scope**:
- `ui/src/lib/store.svelte.ts` (index map + optional batching)
- `ui/src/lib/resultsView.svelte.ts` (lazy/dirty-flag recompute)
- `ui/src/lib/components/ResultsTable.svelte` (only if a pass must move)
- `ui/src/lib/store.test.ts`, `ui/src/lib/resultsView.test.ts` (extend)
- `ui/dist/**` (rebuilt)

**Out of scope** (do NOT touch):
- The SSE client (`api.ts`) event handling shape.
- The DOM render cap value.
- Sort/filter SEMANTICS (order of equal-latency rows, chip behavior, picked
  row logic) — performance-only change.

## Git workflow

- Branch: `advisor/007-results-perf`
- Commits: `test(ui): characterize results view filtering/sorting`, `perf(ui): key-index map for applyResult`, `perf(ui): dirty-flag view recompute instead of per-tick derivation`
- Do NOT push or open a PR unless the operator instructed it.

## Steps

### Step 1: Characterize the current view semantics FIRST

Extend `ui/src/lib/resultsView.test.ts` (from plan 001) with the exact
current behavior: fixture of ~8 rows with duplicate latencies, mixed chips,
rows above/below a maxLatency; assert the full output order of `rows` and the
outputs of `chipRows`/`passedRows`/`tunnelSummary` (whatever is exported —
if these are component-internal, first HOIST them into
`resultsView.svelte.ts` as pure exported functions taking (rows, params) and
have the component call them — pure code motion, no behavior change; rerun
check+tests after the hoist before proceeding).

**Verify**: `npm test` green; this test now pins the semantics the perf steps
must preserve.

### Step 2: Key→index map for applyResult

In `store.svelte.ts` maintain `const resultIndexByKey = new Map<string, number>()`:
- `applyResult` looks up `${ip}:${port}` in the map; on hit, mutate
  `app.results[idx]`; on miss, push and set the map entry.
- Update the map wherever `app.results` is wholesale reassigned:
  `resetResults()` (clear), the hydrate path in `App.svelte` (rebuild — if
  the hydrate loop calls applyResult per row, the map maintains itself; read
  `App.svelte:24-39`), and the `onFinished` replace (read it).
- Export a `rebuildResultIndex()` helper if App.svelte assigns directly.

**Verify**: `npm test` green including a new store test: 1,000 upserts where
500 are updates of existing keys → final array length 500, map size 500,
no duplicates (assert via a key-uniqueness check).

### Step 3: Batch view recomputation during live scans

Choose ONE mechanism, in order of preference:

a) **Dirty flag + lazy derive**: convert `matched`/`rows` in
   `resultsView.svelte.ts` from `$derived` to explicit functions with a
   module-level dirty flag set by `applyResult`/`resetResults` and cleared on
   recompute; `ResultsTable.svelte` calls a single `getView()` in its
   template. Svelte 5 fine-grained rendering means the template still updates
   when the returned array identity changes.
b) **rAF/250 ms flush**: `applyResult` pushes into a pending buffer; a
   `requestAnimationFrame` (fallback `setTimeout` 250) flush moves them into
   `app.results`. Sub-250 ms staleness is invisible at SSE cadence.

Prefer (a) — no staleness at all. If (a) fights how the component consumes
the deriveds, fall back to (b). Either way: the characterization tests from
Step 1 must pass UNCHANGED.

Also collapse the three passes in `ResultsTable.svelte:35-48` into ONE loop
over `rows` producing chipRows/passedRows/summary together (pure
consolidation, same outputs).

**Verify**: `npm test` green (semantics pinned). Manual soak: with the dev
server running, start a CDN scan with a generous target; the results table
stays interactive (scroll/type in the latency filter without multi-second
freezes) as the found count grows into the thousands.

## Test plan

- Step 1's characterization tests are the contract.
- New store test for the index map (Step 2).
- Optional micro-bench (not CI-gating): a vitest timer around 10k applyResult
  calls asserting < 500 ms total — include only if it's stable locally; mark
  `it.skip` otherwise with a comment.

## Done criteria

- [ ] `applyResult` contains no `findIndex`/`filter` over the full array (`rg -n "findIndex" ui/src/lib/store.svelte.ts` → none)
- [ ] View recompute happens at most once per flush/dirty cycle during a live stream (code inspection + tests)
- [ ] Characterization tests pass UNCHANGED from Step 1
- [ ] `cd ui; npm run check && npm test && npm run build` exit 0; dist committed with src

## STOP conditions

- The characterization tests cannot be written because the view logic is
  entangled with component state — report the entanglement; hoist attempt
  failed.
- The dirty-flag approach breaks Svelte 5 reactivity in ways `npm run check`
  or manual testing reveals (stale UI) — switch to mechanism (b) once; if
  that also fails, report.
- Any observable change in row order or filter behavior — revert and report.

## Maintenance notes

- `resultIndexByKey` is now an invariant: ANY code path that reorders or
  filters `app.results` in place (not just appends) must invalidate/rebuild
  the map. Add a one-line WHY comment on the map declaring this.
- If server-side pagination of `/api/results` is ever added, this whole
  client-side view pipeline gets replaced — don't invest beyond this plan.
- Reviewer scrutiny: duplicate `ip:port` rows must remain impossible (map
  guarantees); hydrate path rebuilds the map exactly once per reconnect.
