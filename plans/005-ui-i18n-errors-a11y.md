# Plan 005: Finish UI localization and unify error affordances and a11y semantics

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md`.
>
> **Drift check (run first)**: `git diff --stat 51c4711..HEAD -- ui/src/lib/i18n.svelte.ts ui/src/lib/formState.ts ui/src/lib/components/ProPanel.svelte ui/src/lib/components/WgNoiseEditor.svelte ui/src/lib/components/ResultsTable.svelte ui/src/lib/components/SimpleStart.svelte ui/src/App.svelte ui/src/app.css`
> On mismatch with the excerpts below, STOP.

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: LOW (i18n typing is compile-checked) to MED (FieldIssue refactor touches validation display)
- **Depends on**: plans/001-ui-ci-baseline.md; after 003/004 to avoid merge churn in ProPanel
- **Category**: bug (i18n/a11y)
- **Planned at**: commit `51c4711`, 2026-08-26

## Why this matters

Persian users see English mid-form in high-visibility places: the wgconf
label, the AmneziaWG noise editor headings, icon-button aria-labels, and —
worst — EVERY form-validation message (all of `formState.ts`'s ~23
`FieldIssue.message` strings are English templates rendered under translated
labels). Three different error affordances coexist (native `:user-invalid`
red border, red text without border, one inline style), so users can't
predict what an error looks like. Screen readers get duplicate group names in
Simple mode and continuous chatter from an aria-live region that announces
every progress tick.

## Current state

- `ui/src/lib/i18n.svelte.ts` (499 lines): exports `EN` and `FA` dictionaries;
  `FA` is typed `Record<keyof typeof EN, string>` (around line 234) so key
  parity is a compile error — adding a key to EN without FA fails `npm run check`.
  UNUSED keys today: `pro.warp.wgconfLabel` (EN ~146, FA ~373), `wgnoise.heading*`
  (~220-222/~445-447), `wgnoise.limits` (~226/~451). Also unused (candidates
  for DELETION, verify with grep first): `pro.field.target.hint`,
  `pro.field.customCount`, `pro.phase2.verifyLabel`, `table.results`,
  `table.col.phase2`, `table.phase2.*`, `mode.simple`, `simple.badge.cdn`,
  `simple.testUpTo.hint`.
- Hardcoded English strings (verified locations):
  - `ProPanel.svelte:1237-1238` — `"wgconf (paste your wg:// URI, wg-quick INI, or Amnezia config — enables real-keypair verification)"` (label + aria)
  - `WgNoiseEditor.svelte:196` — `"AmneziaWG noise…"` heading; `:233-235` — limits sentence
  - `ResultsTable.svelte:180` — `title="Every probe ran under your wgconf private key…"`
  - `SimpleStart.svelte:257` — `title="passed a real TLS handshake"`; `:289`, `:309` — English `aria-label`s
  - `App.svelte:129` — `aria-label="Switch language"`
- `ui/src/lib/formState.ts` (~478 lines): `FieldIssue` (interface near the
  top; read it) carries `message: string` built by English template literals
  at lines ~198, 202, 224, 241, 256, 264, 280, 300, 306, 313, 318, 320, 323,
  331, 334, 340, 365, 375, 381, 388, 397, 405, 413. Rendered at
  `ProPanel.svelte:707-716` (inline `fieldError` snippet) and `:844-853`
  (summary list).
- Error styling: `ui/src/app.css:338-340` — `.field:user-invalid` red border
  (native-constraint fields only). `WgNoiseEditor.svelte:219` — inline
  `style="border-color: var(--bad)"`. Routed/custom errors set
  `aria-invalid="true"` but NO CSS targets `[aria-invalid]`.
- `App.svelte:190` — fragile footer split: `footerString.split("db-ip.com")`
  (breaks if a translation drops the domain).
- A11y: `SimpleStart.svelte:109` and `:143` — two different groups share
  `aria-label={t("simple.target")}`. `SimpleStart.svelte:240` —
  `role="status" aria-live="polite"` wraps the whole progress block whose
  counters mutate every second (interval at :44-48). Same pattern at
  `ProPanel.svelte:1522-1530` (phase-2 progress + skip hint). Icon-only
  buttons relying on `title` alone: `ResultsTable.svelte:429-433`, `:441-446`,
  `SimpleStart.svelte:362-368`.
- Headings: `App.svelte:101` is `h1`; ProPanel's first heading (~794) is `h3`
  (skipped level). NOTE: if plan 003/004 landed, line numbers shifted —
  locate by content.

## Commands you will need

| Purpose | Command | Expected |
|---|---|---|
| Typecheck (also validates i18n key parity) | `cd ui; npm run check` | exit 0 |
| Tests | `cd ui; npm test` | all pass |
| Build | `cd ui; npm run build` | exit 0 |
| Find hardcoded strings | `rg -n "\"[A-Z][a-z]+ [a-z]" ui/src/lib/components ui/src/App.svelte` (heuristic sweep) | only intended hits remain |

## Scope

**In scope**:
- `ui/src/lib/i18n.svelte.ts` (new/used/deleted keys, EN + FA)
- `ui/src/lib/formState.ts` (FieldIssue message → key + params)
- `ui/src/lib/components/ProPanel.svelte`, `WgNoiseEditor.svelte`,
  `ResultsTable.svelte`, `SimpleStart.svelte`, `ui/src/App.svelte`
- `ui/src/app.css` (aria-invalid rule)
- `ui/dist/**` (rebuilt)

**Out of scope** (do NOT touch):
- Server-side error strings (`src/server/error.rs` etc.) — routed server
  errors stay as-is this plan.
- The FA translations' tone/style beyond the new strings — mirror existing FA
  entries' register; do not re-translate existing keys.
- Scan behavior, validators' RULES (only their message plumbing changes).

## Git workflow

- Branch: `advisor/005-i18n-errors-a11y`
- Commits: `fix(i18n): route hardcoded strings through existing keys`, `refactor(ui): validation issues carry message keys, resolved via t()`, `fix(ui): one error affordance via aria-invalid`, `fix(a11y): distinct group labels, throttled live region, real icon-button names`
- Do NOT push or open a PR unless the operator instructed it.

## Steps

### Step 1: Use the existing keys; delete truly dead ones

1. Swap the hardcoded strings to their existing keys:
   - ProPanel wgconf label/aria → `t("pro.warp.wgconfLabel")`
   - WgNoiseEditor heading(s) → `t("wgnoise.headingScheme")` /
     `t("wgnoise.headingIni")` (read the keys' exact names at
     `i18n.svelte.ts:220-222` and match which heading is which)
   - WgNoiseEditor limits → `t("wgnoise.limits")`
2. For the five strings with NO key (`ResultsTable:180`, `SimpleStart:257,
   289, 309`, `App:129`): add new keys (suggested names: `table.verifiedTitle`,
   `simple.handshakeTitle`, `simple.resultsAria`, `simple.copyCardAria`,
   `app.switchLanguage`) with EN text copied verbatim from the current
   strings and FA translations in the style of neighboring keys.
3. Replace `App.svelte:190`'s `.split("db-ip.com")` with a two-key approach:
   add `app.footer.geoPrefix` ("GeoIP data by") and `app.footer.geoSuffix`
   ("(CC BY 4.0)") and render `{t(prefix)}<a ...>db-ip.com</a>{t(suffix)}` —
   the link text stays literal "db-ip.com" (attribution requirement, not a
   translation).
4. Grep each candidate-dead key (list above) across `ui/src`; delete only
   those with zero render-site hits, from BOTH dictionaries.

**Verify**: `cd ui; npm run check` exit 0 (key parity enforced);
`rg -n "paste your wg|AmneziaWG noise|Switch language" ui/src` → only i18n
dictionary hits.

### Step 2: Validation messages become keys

1. In `formState.ts`, change `FieldIssue` to carry
   `{ key: string; params?: Record<string, string | number> }` instead of
   `message: string`. Convert all ~23 construction sites: invent stable key
   names mirroring the rules, e.g. `issue.ports.tooMany` with
   `{ max }`, `issue.cidr.invalid`, `issue.endpoint.duplicate` … (name them
   after the RULE, not the current English wording; group by field prefix).
2. Add every key to EN and FA in `i18n.svelte.ts`, translating the current
   English messages' meaning (keep `{param}` interpolation compatible with
   however `t()` does interpolation — read `i18n.svelte.ts`'s `t()`
   implementation first and follow it).
3. In ProPanel's `fieldError` snippet (~707-716) and summary list (~844-853),
   render `t(issue.key, issue.params)`.
4. Server-routed errors (from `ApiError`) keep their server text — they are
   already handled on a separate path; do not route them through keys.

**Verify**: `npm run check` exit 0; switch the UI to FA and trigger three
validation errors (bad port, bad CIDR, empty required field) — each renders
in Persian; switch to EN — same errors in English.

### Step 3: One error affordance

1. In `app.css`, next to the `.field:user-invalid` rule, add:
   ```css
   .field[aria-invalid="true"] { border-color: var(--bad); }
   .field[aria-invalid="true"]:focus-visible { outline-color: var(--bad); }
   ```
   (match the existing rule's exact properties so native and routed errors
   look identical).
2. Remove the inline `style="border-color: var(--bad)"` from
   `WgNoiseEditor.svelte:219` and ensure the editor sets
   `aria-invalid` instead (it likely already does for its error path — read
   it; if not, add `aria-invalid={hasError ? "true" : undefined}` on its
   input).

**Verify**: in the running app, an error from a native constraint (e.g. a
number input below min) and an error from a routed rule look identical (same
border color/width).

### Step 4: A11y semantics

1. `SimpleStart.svelte`: give the size-chip group (~143) a NEW key
   `simple.sizeGroup` (EN "Sample size") as its `aria-label`; leave the mode
   group's label as the mode label. (If plan 003 already did this, verify and
   skip.)
2. Throttle the live region: in `SimpleStart.svelte`, remove
   `aria-live`/`role="status"` from the per-second progress block (~240). Add
   ONE visually-hidden `role="status"` element whose text is a `$derived`
   message updated at most every 10 seconds or when `progress.working`
   changes (implement with a timestamp latch in the component:
   ```ts
   let lastAnnounce = 0;
   const announcement = $derived.by(() => {
     const now = Date.now(); // re-evaluated via the existing interval tick state
     if (now - lastAnnounce < 10_000) return announced;
     lastAnnounce = now;
     announced = t("simple.progressAnnounce", { working: progress.working, checked: progress.checked });
     return announced;
   });
   ```
   Adapt to the component's actual tick mechanism (interval at :44-48 mutates
   a `$state` — read it). Apply the same pattern to ProPanel's phase-2
   progress (~1522-1530).
3. Icon-only buttons: add `aria-label={t(...)}` to
   `ResultsTable.svelte:429-433`, `:441-446` (reuse existing
   `table.copyUriTitle`-style keys if they exist; else add), and
   `SimpleStart.svelte:362-368`. Keep `title` as hover text.
4. Heading hierarchy: change ProPanel's first section heading (~794) from
   `h3` to `h2` (adjust its classes so visual size is unchanged — copy
   classes from the `h3` into the `h2`). Verify no other heading skips
   (App h1 → panel h2 → section h3 is the target outline).

**Verify**: `npm run check` + `npm test` exit 0. Manual: with VoiceOver/NVDA
if available, tab through Simple mode — two group names are distinct; during
a 20-second scan the live region announces at most twice. (If no SR available,
assert DOM: one `role="status"` element whose text changes ≤ once/10s.)

## Test plan

- Extend plan 001's suite with `ui/src/lib/i18n.test.ts`: assert every key in
  EN exists in FA (compile check already does this — instead assert no key
  VALUE in either dictionary contains a literal `"db-ip.com"` split hazard
  and that `t()` interpolation of a sample key with params works).
- Add a formState test: build issues via the exported validation entry points
  with invalid inputs; assert `issue.key` matches the expected rule key and
  params carry the limit values.
- Existing tests stay green.

## Done criteria

- [ ] `rg -n "paste your wg|AmneziaWG noise|passed a real TLS|Switch language" ui/src --glob '!**/i18n.svelte.ts'` returns nothing
- [ ] No `FieldIssue` field named `message` remains (`rg -n "message:" ui/src/lib/formState.ts` → none or only server-error types)
- [ ] `rg -n "aria-invalid" ui/src/app.css` shows the new rule; `rg -n "border-color: var\(--bad\)" ui/src/lib/components` returns nothing
- [ ] FA UI: zero English strings visible in Pro form, WARP group, noise editor, validation errors (manual pass with screenshots)
- [ ] `cd ui; npm run check && npm test && npm run build` exit 0; dist committed with src

## STOP conditions

- The `t()` implementation does not support params — report its actual
  signature; do not build a new i18n layer.
- Any validation message contains data you cannot express as key+params
  (e.g. dynamically computed multi-part sentences) — report the specific
  message; leave that ONE as English with a TODO-free comment is NOT allowed,
  report instead.
- The aria-live throttle fights the component's tick mechanism — report the
  mechanism rather than introducing timers.

## Maintenance notes

- New validation rules MUST add: rule in formState.ts + issue key in BOTH
  dictionaries. The parity type makes missing FA a compile error — keep it.
- The `announcement` latch pattern is the template for any future live region.
- Reviewer scrutiny: FA strings — have a Persian reader (the maintainer) skim
  the new translations; literal correctness over style is fine for this pass.
