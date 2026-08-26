# Plan 006: Fix the UI behavior bugs — results wipe, silent caps, filter-breaking copy, clipboard silence

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md`.
>
> **Drift check (run first)**: `git diff --stat 51c4711..HEAD -- ui/src/lib/store.svelte.ts ui/src/lib/components/ResultsTable.svelte ui/src/lib/components/SimpleStart.svelte ui/src/lib/formState.ts ui/src/lib/validators.ts`
> On mismatch with the excerpts below, STOP.

## Status

- **Priority**: P1
- **Effort**: M (six small fixes, one plan to keep the review single)
- **Risk**: LOW–MED (each fix is local; the results-wipe fix touches the scan-start path)
- **Depends on**: plans/001-ui-ci-baseline.md
- **Category**: bug
- **Planned at**: commit `51c4711`, 2026-08-26

## Why this matters

Five user-facing behavior bugs, each verified in code:

1. **Failed Start wipes the previous scan's results.** `startScan()` calls
   `resetResults()` BEFORE `await api.scan(cfg)`; on a 400/422 or network
   error the user's last completed scan silently disappears (F5 to recover).
2. **Copy-all ignores the latency filter its own tooltip promises.** Users
   who set a latency ceiling paste slow endpoints they believe were filtered.
3. **Simple-mode WARP custom count silently capped at 5,000** while the input
   advertises `max=100000` — the UI shows the entered value, the scan runs 5k.
4. **`warpEndpoints` has no client-side cap** — every sibling list mirrors its
   server cap inline; pasting 3,000 endpoints only fails at request time.
5. **Clipboard failures are silent** — per-row/card copy buttons swallow
   errors (empty catch / no catch), so a denied clipboard permission looks
   like a dead button.

## Current state

- `ui/src/lib/store.svelte.ts:89-117` — `startScan()`:
  ```ts
  if (opts?.preserveResults === true && cfg.phase2_only === true) {
    app.frozenPhase1 = app.results.slice();
  } else {
    resetResults();               // ← wipes BEFORE the request
  }
  app.lastScanConfigs = cfg.phase2?.configs ?? [];
  app.lastScanVerified = cfg.mode === "Warp" && cfg.warp?.verify_with_wgconf === true;
  try {
    await api.scan(cfg);
    ...
  } catch (e) {
    app.error = errorText(e);
    ... return { ok: false, rejected };
  }
  ```
  `resetResults()` is also defined in this file (find it; it clears `results`,
  `summary`, `progress`, `phase2`). Server keeps prior results in memory —
  `App.svelte:24-39` re-pulls them on load/reconnect, which is why F5 "fixes" it.
- `ui/src/lib/components/ResultsTable.svelte:97-101`:
  ```ts
  async function copyAll() {
    await copyText(filteredEndpoints(chipRows, null), chipRows.length);
  ```
  (second arg `null` = latency filter bypassed). The button tooltip key
  `table.copyAllTitle` (i18n ~line 71) says "Copy every **displayed**
  endpoint…". The table itself hides rows above `view.maxLatency`
  (`ui/src/lib/resultsView.svelte.ts:82-88`). Correct precedent:
  `SimpleStart.svelte:93-95` passes `bestView.maxLatency`.
- `ui/src/lib/components/SimpleStart.svelte:163-176` — custom count input
  `max={100000}` and clamp `Math.min(100_000, …)`;
  `ui/src/lib/store.svelte.ts:171-175` — `simpleConfig()` applies
  `target: { Count: Math.min(testCount, 5000) }` for Warp, silently.
- `ui/src/lib/formState.ts:352-360` — the `warpEndpoints` checkLines call
  passes `maxLines: null` (read the exact call; every sibling — ports ~303,
  CIDRs ~349, configs ~378, SNIs ~402 — mirrors its server MAX_* cap).
  Server cap: `MAX_ENDPOINTS = 2048` at `src/api/types.rs:49`.
- Clipboard paths: `ResultsTable.svelte:87-95` (`copyUri` — empty `catch`),
  `SimpleStart.svelte:362-368` (card copy — NO catch). Success-feedback
  helper exists: `announce()` at `ResultsTable.svelte:73-76`; a global error
  banner exists (`app.error`). `store.svelte.ts:232-256` `exportText` shows
  the file-download fallback pattern.

## Commands you will need

| Purpose | Command | Expected |
|---|---|---|
| Typecheck | `cd ui; npm run check` | exit 0 |
| Tests | `cd ui; npm test` | all pass |
| Build | `cd ui; npm run build` | exit 0 |
| Manual | `cargo run -- serve` | behaviors per Done criteria |

## Scope

**In scope**:
- `ui/src/lib/store.svelte.ts`
- `ui/src/lib/components/ResultsTable.svelte`
- `ui/src/lib/components/SimpleStart.svelte`
- `ui/src/lib/formState.ts`
- `ui/src/lib/validators.ts` (export the MAX_ENDPOINTS constant)
- `ui/src/lib/i18n.svelte.ts` (any new hint/announce keys, EN + FA)
- `ui/dist/**` (rebuilt)

**Out of scope** (do NOT touch):
- `src/api/types.rs` or any server cap value — the UI mirrors the server; if
  the caps themselves are wrong that's a separate server decision.
- `startScan`'s `preserveResults`/`frozenPhase1` banked-verify semantics
  (only the reset ORDER changes).
- `App.svelte` (the onFinished refetch swallow is real but low-stakes; noted
  for a future pass — keep this plan's diff reviewable).

## Git workflow

- Branch: `advisor/006-ui-behavior-bugs`
- One commit per numbered fix: `fix(ui): keep previous results when a scan fails to start`, `fix(ui): copy-all honors the latency filter`, `fix(ui): surface the warp 5k sweep cap in simple mode`, `fix(ui): cap warpEndpoints client-side like every other list`, `fix(ui): announce clipboard failures`

## Steps

### Step 1: Reset results only after the scan request succeeds

Restructure `startScan()` so nothing is wiped before the await:

```ts
export async function startScan(cfg, opts?) {
  const preserve = opts?.preserveResults === true && cfg.phase2_only === true;
  if (preserve) app.frozenPhase1 = app.results.slice();
  try {
    await api.scan(cfg);            // server accepted → now reset locally
    if (!preserve) resetResults();
    app.lastScanConfigs = cfg.phase2?.configs ?? [];
    app.lastScanVerified = cfg.mode === "Warp" && cfg.warp?.verify_with_wgconf === true;
    app.running = true;
    app.startedAt = Date.now();
    return { ok: true, rejected: null };
  } catch (e) { ...unchanged catch... }
}
```

Note the ordering subtlety: `resetResults()` must run BEFORE the first SSE
`Result` event can arrive (the EventSource opens on scan start). Since
`api.scan` resolves after the server accepted (read `ui/src/lib/api.ts` —
if it resolves on HTTP 200 BEFORE events flow, the ordering above is safe;
if events can arrive between 200 and resetResults, snapshot-and-restore
instead: snapshot `app.results` before the try, restore it in the catch).
Verify which by reading `api.ts` and pick ONE approach; document the choice
in one WHY comment.

**Verify**: `npm run check`/`npm test` exit 0. Manual: complete a scan (or
fake rows via devtools by pushing into the store), then start a scan that
fails (stop the server first) → previous rows still on screen, error banner
shown.

### Step 2: copyAll honors the latency filter

In `ResultsTable.svelte:97-98` change `filteredEndpoints(chipRows, null)` to
pass the active view's max latency exactly as `SimpleStart.svelte:93-95`
does (read that call; mirror it — likely `view.maxLatency` or
`filteredEndpoints(chipRows, view.maxLatency)` depending on the helper's
signature in `resultsView.svelte.ts`).

**Verify**: set a max-latency filter that hides some rows → Copy all → paste:
hidden rows absent. Tooltip and behavior now agree.

### Step 3: Surface the WARP 5,000 sweep cap

1. In `SimpleStart.svelte`, when `scanMode === "Warp"`, set the custom-count
   input's `max` to 5000 and clamp the bound value to 5000 (replace the
   `100_000` clamps at ~163-176 with a mode-dependent cap constant).
2. Export the constant once — `WARP_SWEEP_CAP = 5000` from
   `validators.ts` (or `cfPorts.ts`-style shared module — pick the module
   that already holds shared scan constants; read them) and import it in
   BOTH `SimpleStart.svelte` and `store.svelte.ts:174`
   (`Math.min(testCount, WARP_SWEEP_CAP)`).
3. When the user's entered value was clamped for Warp, show a one-line muted
   hint under the input (new i18n key `simple.testUpTo.warpCap`, EN:
   "WARP sweeps test at most 5,000 endpoints", FA translated).

**Verify**: Simple mode + WARP + custom 20,000 → input clamps to 5000, hint
visible, `simpleConfig` receives 5000 (assert via the store test below).
CDN mode still allows 100,000.

### Step 4: Mirror MAX_ENDPOINTS client-side

1. Export `MAX_ENDPOINTS = 2048` from `validators.ts` beside the other MAX_*
   constants (mirror comment style; note it must track `src/api/types.rs:49`).
2. In `formState.ts` pass it as the `maxLines` argument of the
   `warpEndpoints` `checkLines` call (~352-360) and word the issue like the
   sibling "at most N lines" messages (new issue key per plan 005's scheme if
   plan 005 landed; else English message matching siblings).

**Verify**: paste 3,000 lines into WARP endpoints → inline error under the
field immediately (not after Start). 2,048 lines → no error.

### Step 5: Clipboard failures announce

1. In `ResultsTable.svelte`: give `copyUri`'s empty catch a body —
   `announce(t("table.copyFailed"))` (or set the same error path the batch
   copy uses; read `copyText` at ~78-85 and route BOTH through a shared
   try/catch that announces failure with the existing `announce()` helper).
2. In `SimpleStart.svelte:362-368`: wrap the `navigator.clipboard.writeText`
   call in try/catch; on failure show the same localized
   `common.copyFailed` key (add to EN + FA; EN: "Copy failed — clipboard
   unavailable"). Offer no fallback dialog; the export path already has the
   file-download fallback for bulk data.

**Verify**: in Chrome devtools revoke clipboard permission (or serve over
http:// on a non-localhost host is not possible here — instead simulate by
temporarily throwing inside writeText) → the announce/toast appears; restore.

## Test plan

- `ui/src/lib/store.test.ts` (new, vitest): 
  - `simpleConfig("Warp", 20000)` → `target.Count === 5000`;
    `simpleConfig("Cdn", 20000)` → 20000.
  - `startScan` failure path: mock `api.scan` to reject → `app.results`
    (pre-seeded) unchanged, `app.error` set. Success path: mock resolves →
    results reset, `running === true`. (Mock via vitest `vi.mock` on
    `ui/src/lib/api.ts`.)
- `validators.test.ts` (from plan 001): add cases for the exported
  `MAX_ENDPOINTS` mirror.
- Existing suite stays green.

## Done criteria

- [ ] Failed scan start leaves prior results visible (manual + store test)
- [ ] Copy-all output equals the displayed (latency-filtered) set
- [ ] WARP custom count clamps to 5000 with a visible hint; constant exported once, used in both files
- [ ] `rg -n "maxLines: null" ui/src/lib/formState.ts` returns nothing
- [ ] No empty catch around clipboard calls (`rg -n "catch {}" ui/src` / `catch {` with empty body)
- [ ] `cd ui; npm run check && npm test && npm run build` exit 0; dist committed with src

## STOP conditions

- `api.scan` resolves only AFTER the SSE stream completes (then the reset
  ordering needs a different design — report what `api.ts` actually does).
- The latency-filter helper's signature cannot express the filtered copy
  without refactoring `resultsView.svelte.ts` — report the signature.
- The 5,000 cap turns out to be enforced (or not enforced) somewhere else
  too (e.g. a server-side WARP target cap) — report where; keep the UI
  constant mirroring the SERVER's real limit, whichever file defines it.

## Maintenance notes

- `WARP_SWEEP_CAP` and `MAX_ENDPOINTS` are now UI-mirrored server constants —
  when `src/api/types.rs` changes them, the grammar-parity/constant tests are
  the tripwire.
- The snapshot-vs-order decision in Step 1 should be recorded in one WHY
  comment — it constrains how `api.scan` may evolve (it must keep resolving
  before the first event, or the snapshot approach must return).
- Reviewer scrutiny: the `preserveResults` banked-verify path must behave
  exactly as before (frozen phase-1 rows + upsert refill) — test verify-banked
  flow manually.
