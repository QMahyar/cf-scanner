# Plan 003: Repair the Pro form layout — one grid, aligned fields, no duplicates

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md`.
>
> **Drift check (run first)**: `git diff --stat 51c4711..HEAD -- ui/src/lib/components/ProPanel.svelte ui/src/lib/components/SimpleStart.svelte ui/src/app.css`
> On any mismatch with the excerpts below, STOP.

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: MED (visual regressions possible; mitigated by screenshot checks)
- **Depends on**: plans/001-ui-ci-baseline.md (so `npm run check`/`npm test` gate every step)
- **Category**: bug (layout/UX)
- **Planned at**: commit `51c4711`, 2026-08-26

## Why this matters

The maintainer's own complaint: "the fields and the options are all over the
place — don't look nice positionally and UX-wise." Root causes verified in
code and in the live UI: (1) commit `a59d739` added an on-demand Custom-ports
input but failed to delete the old always-visible one, so the same field
renders TWICE with duplicate DOM ids; (2) the scan grid mixes span breakpoints
and full-span rows for tiny fields, leaving visible holes; (3) six different
grid systems and five different numeric field widths coexist, so nothing
aligns; (4) the mode selector is a segmented pill group in Simple mode but a
`<select>` in Pro mode; (5) the sticky action bar's negative margins don't
match its parent's responsive padding, so the CTA row sits visibly crooked
from `sm:` up.

## Current state

All in `ui/src/lib/components/ProPanel.svelte` (1,598 lines at `51c4711`)
unless noted:

- **Duplicate Custom-ports field.** On-demand copy (correct one, behind
  `{#if customPortsOpen}`) at lines 983–996:
  ```svelte
  {#if customPortsOpen}
    <label class="mt-1.5 block text-xs" style="color: var(--ink-muted)">
      {t("pro.field.customPorts")}
      <input class="field mono mt-1" name="customPortsText" ... bind:value={form.customPortsText} />
      {@render fieldError("customPortsText")}
    </label>
  {/if}
  ```
  Orphan duplicate (the regression) at lines 1022–1033 — an UNCONDITIONAL
  `<label>` with the SAME `{t("pro.field.customPorts")}` text, SAME
  `name="customPortsText"`, SAME `bind:value={form.customPortsText}`, SAME
  `err-customPortsText` aria-describedby id.
- **Grid container** at line 855: `class="... grid gap-x-4 gap-y-3 md:grid-cols-2 lg:grid-cols-3"`
  (read the exact line for the full class list).
- **Span inconsistencies**: `stopAfter` label at 1035–1050 spans
  `md:col-span-2 lg:col-span-3` for a `max-w-40` input; the orphan ports label
  (1022) spans 1 column leaving 2 empty cells; the tuning disclosure wrapper at
  1055 uses `md:col-span-2 lg:col-span-3`; line 934 uses a `sm:col-span-2`
  prefix against the container's `md:` breakpoint. Other grids in the same
  file: line 1060 (`sm:grid-cols-2 lg:grid-cols-3`), 1119 and 1187 and 1235
  (`sm:grid-cols-2`), 1421 (`sm:grid-cols-3`), 1536 (`lg:grid-cols-2`).
- **Numeric width chaos**: `ProPanel.svelte:902` (`!w-28`), `:1041`
  (`max-w-40`), `:1311` (`!w-56`); `SimpleStart.svelte:164` (`!w-24`), `:199`
  (`!w-20`); full-width numeric inputs at `ProPanel.svelte:1063/1077/1092`.
- **Mode widget split**: `SimpleStart.svelte:105-129` renders CDN/WARP as a
  segmented pill group (buttons with `aria-pressed`); `ProPanel.svelte:856-861`
  renders the same choice as `<select bind:value={form.mode}>`. ProPanel also
  already contains a segmented pattern for results tabs around lines 1556–1580.
- **Sticky action bar** at `ProPanel.svelte:1461`: negative margins
  `-mx-6 -mb-6 ... px-6 pt-3`, but its parent `.core` container at line ~721
  uses `px-6 py-8 sm:px-8 sm:py-10` — the bar is inset 0.5rem from card edges
  at ≥sm.
- Design system: Tailwind 4 utility classes + CSS variables from
  `ui/src/app.css` (`--ink-muted`, `--paper-3`, `--accent`, `--accent-ink`,
  `--bad`). Existing field styling: `.field` class (see `app.css`), `.pill`
  for toggle chips, `.mono` for monospace.

Conventions: Svelte 5 runes-only; `t()` from `ui/src/lib/i18n.svelte.ts` for
ALL user-visible strings (EN/FA parity is compile-checked — new keys must be
added to BOTH dictionaries); commit `ui/src` together with rebuilt `ui/dist`.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Install deps | `cd ui; npm ci` | exit 0 |
| Typecheck | `cd ui; npm run check` | exit 0 |
| Unit tests | `cd ui; npm test` | all pass (from plan 001) |
| Build + embed | `cd ui; npm run build` | exit 0; `ui/dist` updated |
| Manual visual check | `cargo run -- serve` then open http://127.0.0.1:8765 | form renders per Done criteria |

## Scope

**In scope**:
- `ui/src/lib/components/ProPanel.svelte`
- `ui/src/lib/components/SimpleStart.svelte` (only the numeric-width classes and mode-group label, see steps)
- `ui/src/app.css` (add shared utilities: `.grid-form`, `.field-num`)
- `ui/src/lib/i18n.svelte.ts` (only if a new key is needed for the mode group label)
- `ui/dist/**` (rebuilt)

**Out of scope** (do NOT touch):
- `ui/src/lib/formState.ts`, `ui/src/lib/store.svelte.ts` — no state/logic changes in this plan (behavior fixes live in plan 006; preset unification is explicitly deferred, see Maintenance).
- `WgNoiseEditor.svelte` internal grid (documented exception; only its inline error style is touched, in plan 005).
- Any Rust file, the API, or scan defaults.
- ResultsTable.svelte.

## Git workflow

- Branch: `advisor/003-pro-form-layout`
- Commits: `fix(ui): drop duplicated custom-ports field (a59d739 regression)`, `fix(ui): one form grid + aligned numeric widths`, `feat(ui): segmented mode control in pro form`, `fix(ui): sticky action bar responsive inset`
- Do NOT push or open a PR unless the operator instructed it.

## Steps

### Step 1: Delete the orphan duplicate Custom-ports field

In `ui/src/lib/components/ProPanel.svelte`, delete lines 1022–1033 (the
unconditional `<label>` block containing `name="customPortsText"` that is NOT
inside `{#if customPortsOpen}`). Keep the `{#if customPortsOpen}` block at
983–996 untouched.

**Verify**: `cd ui; npm run check` → exit 0. `rg -c "customPortsText" ui/src/lib/components/ProPanel.svelte` → the string appears in: the on-demand input, `fieldErrors` references, and formState — but exactly ONE `<input` with `name="customPortsText"`. In the running app (`cargo run -- serve` after `npm run build`), the Custom-ports input appears only when the "Custom" chip is pressed.

### Step 2: Introduce the two shared layout utilities in app.css

Add to `ui/src/app.css` (near the existing `.field` definitions; match the
file's custom-layer structure — read the top of the file first):

```css
/* Canonical form grid: 1 col mobile, 2 cols ≥sm, 3 cols ≥lg. */
.grid-form { display: grid; gap: 0.75rem 1rem; grid-template-columns: 1fr; }
@media (min-width: 640px) { .grid-form { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
@media (min-width: 1024px) { .grid-form { grid-template-columns: repeat(3, minmax(0, 1fr)); } }
/* Numeric fields: fixed ch width, mono, centered. */
.field-num { width: 10ch; text-align: center; }
```

If the project prefers Tailwind utilities over component classes, instead add
these as `@utility` definitions (Tailwind 4 syntax — check how existing custom
classes in `app.css` are declared and follow THAT pattern; the class names
`.grid-form`/`.field-num` stay the same either way).

**Verify**: `cd ui; npm run check && npm run build` → exit 0.

### Step 3: Convert every form section to the canonical grid

In `ProPanel.svelte`:

1. Replace the scan-config grid container class (line ~855) so it uses
   `grid-form` (drop its own `md:grid-cols-2 lg:grid-cols-3`).
2. Do the same for the section grids at lines ~1060, ~1119, ~1187, ~1235,
   ~1421. For grids that genuinely need 2 columns at desktop only
   (line ~1536), use `grid-form` too — 3 columns is fine for pairs; if a
   section visually requires exactly 2, keep `sm:grid-cols-2` but add a
   one-line WHY comment.
3. Fix spans: every direct child is either single-column (no span class) or
   full-width (`col-span-1 sm:col-span-2 lg:col-span-3` — define this once as
   `.span-all` in app.css alongside `grid-form` and use it). Convert:
   - `stopAfter` (1035–1050): single column, NOT full-span. Its input gets
     `field-num`.
   - tuning disclosure wrapper (1055): `span-all`.
   - line ~934's `sm:col-span-2`: `span-all` or single column, whichever the
     content is (read it: if it's one field, drop the span).
4. Numeric widths: apply `field-num` to integer inputs — `count` (~902),
   `stopFound` (~1041), concurrency/timeout/cap (~1063/1077/1092 — these may
   keep wider `field-num` variants; use `width: 12ch` via a `.field-num-wide`
   if needed). In `SimpleStart.svelte`, replace `!w-20`/`!w-24` with
   `field-num` (~164, ~199). Keep `license` (`!w-56`, ~1311) as-is — it's a
   token, not a number.

**Verify**: build + serve; at 1440px, 768px, and 390px widths confirm: no
empty grid cells in the scan-config section; stop-after sits in one column;
all integer inputs share one width. `npm run check` exit 0.

### Step 4: Segmented mode control in Pro

1. In `SimpleStart.svelte:105-129`, read the existing segmented pill-group
   markup (buttons + `aria-pressed` + group `role="group"` + `aria-label`).
2. Create `ui/src/lib/components/Segmented.svelte`:
   ```svelte
   <script lang="ts">
     let { options, value, onchange, label }: {
       options: { value: string; label: string }[];
       value: string;
       onchange: (v: string) => void;
       label: string;
     } = $props();
   </script>

   <div role="group" aria-label={label} class="flex gap-1.5">
     {#each options as opt (opt.value)}
       <button type="button" class="pill" aria-pressed={value === opt.value}
         onclick={() => onchange(opt.value)}>{opt.label}</button>
     {/each}
   </div>
   ```
   Match the exact pill styling used by SimpleStart (copy its classes; the
   selected style is the inline `background: var(--accent); color:
   var(--accent-ink)` pattern from ProPanel port pills).
3. Use it for mode in ProPanel (replace the `<select>` at ~856–861, options
   `Cdn`/`Warp` with their `t()` labels) and refactor SimpleStart's mode group
   and size chips to use it too (three call sites total; results tabs at
   ~1556–1580 may adopt it if trivial — optional).
4. The mode group's `aria-label` must differ from SimpleStart's size group
   label (audit finding: both currently say `t("simple.target")`). Give the
   size group a new key `simple.sizeGroup` ("Sample size" / FA equivalent) in
   BOTH i18n dictionaries; keep mode group label as the mode label.

**Verify**: `npm run check` exit 0; in the running app, Pro mode shows pills
for CDN/WARP; keyboard Tab+Space toggles mode; `aria-pressed` present in DOM.

### Step 5: Sticky action bar inset

At `ProPanel.svelte:1461` change the negative margins/padding to mirror the
parent's responsive scale: `-mx-6 sm:-mx-8 -mb-8 sm:-mb-10 px-6 sm:px-8 pt-3`
(read the current classes first and only adjust the breakpoint-dependent
values; keep blur/styling classes untouched).

**Verify**: build + serve at ≥640px width: the action strip is flush with the
card's left/right/bottom edges (no 0.5rem sliver). `npm run check` exit 0.

## Test plan

- Plan 001's suite must stay green (`cd ui; npm test`).
- Add `ui/src/lib/components/Segmented.test.ts` if `@testing-library/svelte`
  was installed in plan 001: renders one button per option, `aria-pressed`
  reflects `value`, click calls `onchange`. If component testing isn't set up
  yet, skip this file — the harness plan owns it.
- Manual visual verification at 1440/768/390 px is part of Done criteria
  (screenshots in the PR/report).

## Done criteria

- [ ] Exactly one `<input name="customPortsText">` exists in ProPanel source
- [ ] `rg -n "sm:col-span|md:col-span|lg:col-span" ui/src/lib/components/ProPanel.svelte` shows only `span-all`-style full spans (or none) — no mixed prefixes against the canonical grid
- [ ] All integer inputs use `.field-num` (grep `w-20|w-24|w-28|max-w-40` returns no numeric-field hits; `w-56` license exempt)
- [ ] Mode is a segmented control in BOTH panels; size-group aria-label ≠ mode-group aria-label
- [ ] `cd ui; npm run check && npm test && npm run build` all exit 0
- [ ] `ui/dist` committed together with `ui/src`
- [ ] No files outside scope modified

## STOP conditions

- The orphan duplicate block at 1022–1033 is not present as described (already
  fixed or moved) — verify against live code, report if the regression looks
  different than documented.
- Removing the duplicate breaks svelte-check because something else referenced
  its unique attributes (it shouldn't — both copies are identical).
- The `Segmented.svelte` extraction would require changing `form.mode`'s type
  or the profile-load hydration path (mode changes have a reset side effect
  wired in an `$effect` — if you find mode switching triggers port resets via
  effects, leave the effect untouched and report; its replacement is plan-006/
  SVX-04 territory).
- Visual check at any width shows a worse layout than before — revert the
  specific step and report.

## Maintenance notes

- `.grid-form`/`.field-num`/`.span-all` are now the canonical layout
  primitives — new form sections must use them, not bespoke grids.
- The Simple↔Pro preset drift (Large ~50K vs Full 1.5M; separate preset tables
  in `store.svelte.ts:166-202` vs `formState.ts:83-108`) is deliberately NOT
  fixed here — it changes scan behavior and belongs in its own plan with the
  maintainer's sign-off on defaults.
- Reviewer scrutiny: the mode control swap touches the most state-sensitive
  control in the app; verify profile load → mode pill state stays in sync
  (load a profile with the opposite mode and check the pills).
