# Plan 009: Decompose ProPanel.svelte into section components along its existing seams

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md`.
>
> **Drift check (run first)**: `git diff --stat 51c4711..HEAD -- ui/src/lib/components/ProPanel.svelte`
> This plan is written against the post-003/004/005 shape of ProPanel. If
> those plans have NOT landed yet, STOP — the line numbers and seams this
> plan references assume them.

## Status

- **Priority**: P3
- **Effort**: L (spread over many small, verifiable extractions)
- **Risk**: MED (runes state/props design per extraction)
- **Depends on**: plans/001, 003, 004, 005, 006, 007 (the form must be layout-stable before it is cut apart)
- **Category**: tech-debt
- **Planned at**: commit `51c4711`, 2026-08-26

## Why this matters

`ProPanel.svelte` is the largest file in the UI (1,598 lines at `51c4711`;
still four figures after the layout plans). Its script block holds ~30
functions spanning six concerns (file import, phase-2 orchestration, results
view models, profiles CRUD, xray management, WARP registration), and the
duplicate-field regression that plan 003 fixes happened precisely because
every feature edits the same 700-line scope. The template already has eight
visually distinct sections; the repo has an in-house precedent for this
medicine (the 3.2k-line server god file was split the same way) and a
working exemplar of small components (`WgNoiseEditor.svelte`). Decomposition
makes every future UI change reviewable in slices.

## Current state

At `51c4711` (adjust for the earlier plans' edits — locate by content, the
seams are stable):

- Template sections (line ranges at `51c4711`): profiles bar ~722–781; scan
  config header/form ~795–1050; advanced tuning disclosure ~1056–1115;
  custom CIDRs ~1117–1179; WARP advanced ~1183–1233; WARP
  identity/registration ~1235–1377 (regrouped by plan 004); phase-2 tunnel
  card ~1380–1456; sticky actions ~1458–1500; results tabs ~1502+.
- Script concerns (function names at `51c4711`): `loadWgconfFile` (~98),
  `importRangesFile` (~131), `waitForIdle` (~212), `skipToPhase2` (~224),
  `verifyBanked` (~268), results view models (~304–325), profiles CRUD
  (~562–616), xray management (~617–636), `registerWarp` (~641), `copyConf`
  (~656), `useRegisteredConf` (~666).
- State: `form` (from `formState.ts`), `app` (from `store.svelte.ts`), plus
  local UI state (`customPortsOpen`, `scanAdvancedOpen`, disclosure flags,
  registration state).
- Exemplar small component: `ui/src/lib/components/WgNoiseEditor.svelte` —
  props-in/callbacks-out, owns its local state. Follow its API style.
- Conventions: Svelte 5 runes (`$props`, `$state`, `$derived`, callback
  props — NO `createEventDispatcher`, NO `export let`); `t()` inside
  components via the shared i18n module; commit `ui/dist` with `ui/src`.

## Commands you will need

| Purpose | Command | Expected |
|---|---|---|
| After EVERY extraction | `cd ui; npm run check && npm test && npm run build` | all exit 0 |
| Manual smoke | `cargo run -- serve` | Pro form fully functional |

## Scope

**In scope**:
- `ui/src/lib/components/ProPanel.svelte` (shrinks)
- NEW: `ui/src/lib/components/ProfilesBar.svelte`,
  `XrayStatusCard.svelte` (or fold into Phase2TunnelCard per plan 004's
  placement), `WarpIdentityCard.svelte`, `WarpRegistrationCard.svelte`,
  `Phase2TunnelCard.svelte`, `CustomCidrsCard.svelte`
- `ui/dist/**` (rebuilt)

**Out of scope** (do NOT touch):
- `formState.ts`, `store.svelte.ts`, `validators.ts` — no state-model changes.
  If an extraction seems to require changing them, STOP.
- `SimpleStart.svelte`, `ResultsTable.svelte`, `App.svelte`.
- Any behavior change, however tempting (that's plans 003–007's territory,
  already landed).

## Git workflow

- Branch: `advisor/009-propanel-decomposition`
- ONE commit per extracted component: `refactor(ui): extract ProfilesBar from ProPanel`, etc. Each commit must pass the full gate — the app builds and works after every commit.

## Steps

Extract leaf-first. After each step, run the full gate and manually smoke the
affected section (open/close its disclosure, exercise its main button).

### Step 1: Extract ProfilesBar

Move the profiles bar markup (~722–781) and its handlers (`loadProfiles`,
`saveProfile`, `deleteProfile`, name input state) into
`ProfilesBar.svelte`. Props: none beyond what it reads from `app`/`form` —
pass `form` (for load-into-form) as a prop and call a shared
`loadSelectedProfile` via callback prop `onload` OR import the store
functions directly (they are module exports in `store.svelte.ts` — prefer
direct imports for store actions, props for `form`).

**Verify**: gate green; save/load/delete a profile in the running app.

### Step 2: Extract CustomCidrsCard

Move the Custom CIDRs disclosure (~1117–1179) + `importRangesFile` +
`cidrsText`-related local state. Props: `form` (bind via `bind:` is NOT
allowed across new components for form fields — pass `form` object and mutate
its properties directly; Svelte 5 deep proxies make this reactive; this
matches how `WgNoiseEditor` receives state). Include the ranges-info line
plan 004 moved here.

**Verify**: gate green; CIDR import from file works; validation error shows
under the CIDR field on bad input.

### Step 3: Extract Phase2TunnelCard

Move the tunnel-test card (~1380–1456) including the xray chip + Download
button (plan 004's placement), `skipToPhase2`, `verifyBanked`, `waitForIdle`,
and the advanced tunnel settings disclosure. Props: `form`, plus callbacks
that must reach the parent (`onStartVerify` if it triggers the parent's scan
flow — read `verifyBanked`'s body; whatever store functions it calls can be
imported directly).

**Verify**: gate green; paste a config, run verify-banked after a scan,
fragment preset disclosure opens.

### Step 4: Extract WarpIdentityCard and WarpRegistrationCard

Split plan 004's identity group: `WarpIdentityCard` (wgconf textarea, Load
.conf, noise editor, verify checkbox + hint) and `WarpRegistrationCard`
(license input, register button, registered-conf output, `registerWarp`,
`copyConf`, `useRegisteredConf`). Registration async state (`registering`,
error, result) moves INTO `WarpRegistrationCard` as local `$state`.

**Verify**: gate green; full WARP flow: paste wgconf → checkbox enables →
register (with a throwaway identity or mocked failure) → copy conf.

### Step 5: Shrink the ProPanel shell

What remains in ProPanel: the mode/target/ports grid, advanced tuning
disclosure, the sticky action bar, results tabs, and the composition of the
extracted cards. Target: under ~500 lines. Move any now-orphaned helpers to
the component that uses them; delete nothing that is still referenced.

**Verify**: gate green; `Get-Content ui/src/lib/components/ProPanel.svelte | Measure-Object -Line` → < 520; full manual pass over ALL Pro sections.

## Test plan

- Suite from plan 001 stays green throughout.
- If plan 001 installed `@testing-library/svelte`, add one render test per new
  component (renders, main callback fires) — keep them minimal; the manual
  smoke is the deeper check.
- Manual smoke checklist per step (run it): profiles CRUD; CIDR import;
  config paste + verify-banked; WARP identity + registration; scan start from
  the sticky bar; results tabs.

## Done criteria

- [ ] ProPanel.svelte < 520 lines; six new component files exist and are each < 400 lines
- [ ] No `createEventDispatcher`, no `export let`, no `<slot>` in the new components (`rg -n "createEventDispatcher|export let|<slot>" ui/src/lib/components/{ProfilesBar,XrayStatusCard,WarpIdentityCard,WarpRegistrationCard,Phase2TunnelCard,CustomCidrsCard}.svelte` → nothing)
- [ ] Every intermediate commit passed check+test+build (verify via git log)
- [ ] Full manual smoke checklist passes
- [ ] `ui/dist` committed with src

## STOP conditions

- An extraction requires changing `formState.ts`/`store.svelte.ts` (state
  model) — report which state and why; the plan forbids it.
- Two-way reactivity breaks (a child mutating a prop doesn't update the
  parent view) — verify you're mutating the passed `form` OBJECT's
  properties, not rebinding; if a genuine Svelte 5 limitation appears, report
  the exact case.
- `svelte-check` reports prop-type errors you cannot resolve without `any` —
  report; do not weaken types.
- Any behavior regression in the manual smoke — revert that extraction, report.

## Maintenance notes

- New sections in the Pro form should become new components from day one;
  ProPanel remains the composer + owner of `form`.
- The extraction order (leaf-first) was chosen so each commit is revertible
  independently.
- Reviewer scrutiny: props flow — no component should import `formState`'s
  `form` singleton directly if it received it as a prop (mixing the two
  defeats the seam); grep for it in review.
