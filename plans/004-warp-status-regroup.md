# Plan 004: Regroup the WARP section and relocate environment status out of the form header

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md`.
>
> **Drift check (run first)**: `git diff --stat 51c4711..HEAD -- ui/src/lib/components/ProPanel.svelte ui/src/lib/i18n.svelte.ts`
> On mismatch with the excerpts below, STOP.

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: LOW–MED (pure relocation; bindings must not move)
- **Depends on**: plans/001-ui-ci-baseline.md; best after plans/003 (grid utilities exist)
- **Category**: bug (UX/information architecture)
- **Planned at**: commit `51c4711`, 2026-08-26

## Why this matters

Setting up WARP verification — the single most involved task in the Pro form —
is smeared across three stacked blocks: the wgconf paste area, an orphaned
"verify with this identity's real keypair" checkbox (disabled with no
explanation until a wgconf is provided), and the registration box, with the
endpoint-import field wedged in between. Meanwhile the "Scan configuration"
header carries infrastructure status (xray found/missing pill, Download
button, Range info button) that competes with the form title, and the ranges
factoid renders far from the Custom-CIDRs disclosure it describes. Verified
live in the running UI. Users hunt vertically for related controls.

## Current state

All in `ui/src/lib/components/ProPanel.svelte` at `51c4711`:

- Lines ~797–829: the "Scan configuration" section header row contains the
  xray status pill (`xray v26.3.27` / found-or-missing), a Download button,
  and a "Range info" button, sharing the row with the `h3` section title.
- Lines ~838–842: a sentence rendering ranges info (N hosts · last updated)
  directly under the header — far from the Custom-CIDRs disclosure at
  ~1115–1179 which is where CIDR-related controls live.
- Lines ~1181–1233: `<details>` "Advanced WARP options" containing probes-per-
  endpoint and the warpEndpoints textarea.
- Lines ~1235–1300: OUTSIDE any disclosure — the wgconf paste label +
  textarea + "Load .conf file" button, then the `verifyWarp` checkbox at
  ~1297–1300 with `disabled={!form.wgconf}` and no hint text.
- Lines ~1302–1377: the registration card (WARP+ license input, Register
  identity button, registered-conf output).
- Line ~1490–1492: the disabled Verify-banked button whose `title` falls back
  to `t("pro.phase2.configsLabel")` ("Configs to verify through the tunnel…")
  — a field label, not a reason.
- i18n: `ui/src/lib/i18n.svelte.ts` — EN dictionary around line 146 has
  `pro.warp.wgconfLabel` (currently UNUSED; the wgconf label at ProPanel:1237-1238
  is a hardcoded English string — that string swap happens in plan 005; this
  plan only moves the block).

Conventions: Svelte 5 runes-only; `t()` for all strings; commit `ui/src` +
rebuilt `ui/dist` together; use the `grid-form`/`span-all` utilities from
plan 003 for any new grids.

## Commands you will need

| Purpose | Command | Expected |
|---|---|---|
| Typecheck | `cd ui; npm run check` | exit 0 |
| Tests | `cd ui; npm test` | all pass |
| Build | `cd ui; npm run build` | exit 0 |
| Manual check | `cargo run -- serve` → http://127.0.0.1:8765 | WARP section reads as ONE group |

## Scope

**In scope**:
- `ui/src/lib/components/ProPanel.svelte`
- `ui/src/lib/i18n.svelte.ts` (new keys for the verify-checkbox hint and disabled reasons — BOTH EN and FA dictionaries)
- `ui/dist/**` (rebuilt)

**Out of scope** (do NOT touch):
- Any `bind:value` targets, `form` fields, or store logic — this plan MOVES
  markup, it does not change state flow.
- The hardcoded-English → `t()` swaps (plan 005) except the two NEW keys this
  plan introduces.
- `SimpleStart.svelte`, `ResultsTable.svelte`, `WgNoiseEditor.svelte` markup
  order.
- Rust/server files.

## Git workflow

- Branch: `advisor/004-warp-regroup`
- Commits: `refactor(ui): group warp identity + verification + registration`, `refactor(ui): move xray/range status out of the scan header`, `feat(ui): explain disabled verify controls`
- Do NOT push or open a PR unless the operator instructed it.

## Steps

### Step 1: Rebuild the WARP section as two labeled groups

Target structure inside the WARP-visible region (keep the existing
`{#if form.mode === "Warp"}` guards — read the current conditionals first):

1. Keep "Advanced WARP options" `<details>` (~1181–1233) as-is, containing
   probes + endpoints.
2. Directly after it, create a bordered group (match the styling of the
   existing registration card's container classes) titled with a NEW i18n key
   `pro.warp.identityGroup` (EN: "Identity & verification", FA: translate —
   ask the maintainer or mirror the tone of existing FA strings like the ones
   around `pro.warp.*` keys) containing IN THIS ORDER:
   - the wgconf label + textarea + "Load .conf file" button (from ~1235–1260),
   - the noise editor (`WgNoiseEditor` component invocation, currently inside
     this region),
   - the `verifyWarp` checkbox (from ~1297–1300).
3. After it, the registration card (~1302–1377) unchanged except its position.
4. The `verifyWarp` checkbox gets a muted hint line under it with new key
   `pro.warp.verifyHint` (EN: "Requires a wgconf above — verifies candidates
   with your real keypair", FA equivalent). Show it always (not only when
   disabled) so the dependency is discoverable.

**Verify**: `npm run check` exit 0; in the running app with mode=WARP: one
visual group contains wgconf + noise + verify checkbox; registration follows;
probes/endpoints remain in Advanced. Toggle mode CDN↔WARP — no console errors,
bindings still save into profiles (save/load a profile round-trip).

### Step 2: Move environment status out of the scan header

1. Remove the xray pill + Download button + Range info button from the
   section-header row (~797–829), leaving the header with just the title.
2. Place the xray status chip INSIDE the "Tunnel test" (phase-2) card —
   it is only relevant when phase-2 verification is on (the card at
   ~1380–1456; put the chip in that card's header row).
3. Place the Range info button + the ranges sentence (~838–842) INSIDE the
   "Custom CIDRs & exclusions" `<details>` (~1115–1179), directly above the
   CIDR textareas — that is the data it describes.
4. The Download button stays next to the xray chip wherever it lands (phase-2
   card header).

**Verify**: build + serve: scan header shows only the title; ranges info is
visible when the CIDRs disclosure is open; xray chip appears in the tunnel
card. `npm run check` exit 0.

### Step 3: Explain disabled verify controls

1. Add a `$derived` in ProPanel's script:
   ```ts
   const verifyBankedDisabledReason = $derived.by(() => {
     if (!form.phase2) return t("pro.verify.reason.phase2Off");
     if (form.phase2.configs.length === 0) return t("pro.verify.reason.noConfigs");
     if (app.results.length === 0) return t("pro.verify.reason.noCandidates");
     return "";
   });
   ```
   (Read the actual field names in `formState.ts`/`store.svelte.ts` for
   phase2-on, configs, and banked candidates — mirror how the button's
   current `disabled` expression at ~1490 computes it, and reuse those exact
   conditions so the reason can never disagree with the disabled state.)
2. Bind `title={verifyBankedDisabledReason || t("pro.verify.title")}` on the
   Verify-banked button; add `aria-describedby` pointing at a visually-hidden
   element carrying the same string when disabled.
3. Add three new i18n keys `pro.verify.reason.*` (EN + FA) with short human
   reasons.

**Verify**: in the running app, hover/focus the disabled Verify button →
tooltip states the actual missing precondition; with phase-2 off it says so;
with a config pasted and a completed scan it becomes enabled.

## Test plan

- Existing suite from plan 001 stays green.
- Manual regression: profile save/load across the moved blocks (wgconf text,
  verifyWarp flag, license) — values persist and rehydrate into the NEW
  positions.
- Screenshots before/after at 1440px and 390px attached to the report.

## Done criteria

- [ ] WARP identity/verify/registration form one visual group; probes/endpoints stay in Advanced
- [ ] Verify checkbox has a persistent hint naming its wgconf dependency
- [ ] Scan-configuration header contains only the title; xray chip + Download live in the tunnel card; ranges info lives inside the CIDRs disclosure
- [ ] Disabled Verify button's tooltip states a concrete missing precondition (never a field label)
- [ ] `cd ui; npm run check && npm test && npm run build` exit 0; dist committed with src
- [ ] No `bind:` targets changed (`git diff` shows moved markup, not re-bound state)

## STOP conditions

- The moved blocks are guarded by conditionals you cannot preserve (e.g. the
  registration card renders in CDN mode too) — report the actual conditional
  structure instead of guessing.
- Profile round-trip loses any field after the move (hydration depends on DOM
  order somewhere) — revert the move and report; that would make this a state
  bug, not a layout move.
- New i18n keys cannot be added because the dictionaries' key-typing rejects
  the approach described — report the actual typing mechanism.

## Maintenance notes

- The two new groups are the natural seams for plan 009's component
  extraction (`WarpRegistrationCard.svelte` etc.) — keep the group containers
  as single root elements to make that extraction mechanical.
- If a third scan mode ever exists, the "Advanced …options" + identity-group
  pattern should be replicated per mode, not merged.
- Reviewer scrutiny: confirm the xray Download button did not become
  reachable in a state where it wasn't before (same guards as before, new
  position only).
