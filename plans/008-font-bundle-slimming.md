# Plan 008: Slim the embedded UI bundle — drop dead font payload

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md`.
>
> **Drift check (run first)**: `git diff --stat 51c4711..HEAD -- ui/package.json ui/src/app.css ui/src/main.ts`
> On mismatch with the excerpts below, STOP.

## Status

- **Priority**: P3
- **Effort**: S
- **Risk**: LOW (font rendering must be re-verified visually, esp. Persian)
- **Depends on**: plans/001-ui-ci-baseline.md
- **Category**: perf / tech-debt
- **Planned at**: commit `51c4711`, 2026-08-26

## Why this matters

About 130 KB of the ~461 KB committed `ui/dist` is font payload no browser
ever fetches, but rust-embed bakes it into the release binary: the
`@fontsource-variable/inter` package is declared and imported NOWHERE (Inter
was removed from the design in 0.9.0 per CHANGELOG); `@fontsource/jetbrains-mono/400.css|600.css`
pull both modern woff2 AND legacy woff files; and Vazirmatn's latin/latin-ext
subsets are shadowed by the font stacks in `app.css` (Latin resolves via Plus
Jakarta Sans / Space Grotesk first), leaving only the arabic subset useful.
`ui/dist` is tracked in git, so this is also repo weight.

## Current state

- `ui/package.json:22` — `"@fontsource-variable/inter": "^5.2.8"` under
  dependencies. `rg -n "inter" ui/src` (case-insensitive, word-ish) → no
  import; `rg -n "Inter" ui/dist/assets/*.css` → no hits.
- `ui/src/app.css:3-4` — `@import "@fontsource/jetbrains-mono/400.css";` and
  `@import "@fontsource/jetbrains-mono/600.css";` (read exact lines). These
  generic entries reference woff2 + woff; dist emits four jetbrains-mono
  files (~76 KB total, two of them legacy `.woff`).
- `ui/src/app.css:83,92` — font stacks: Latin text resolves
  `"Plus Jakarta Sans"`/`"Space Grotesk"` BEFORE `"Vazirmatn"`; Vazirmatn is
  only reached for Arabic-script glyphs.
- Vazirmatn import (find it in `app.css` top): `@fontsource-variable/vazirmatn`
  default entry loads ALL subsets (arabic ~46 KB used; latin+latin-ext ~56 KB
  dead).
- Space Grotesk already uses hand-written `@font-face` blocks with explicit
  woff2 files somewhere in `app.css` — THAT is the pattern to copy.
- Build rule: `cd ui && npm run check && npm run build`, commit `ui/dist`
  with `ui/src`.

## Commands you will need

| Purpose | Command | Expected |
|---|---|---|
| Confirm inter unused | `rg -in "fontsource-variable/inter|'Inter'|\"Inter\"" ui/src` | no hits |
| Build | `cd ui; npm run build` | exit 0 |
| Size check | `Get-ChildItem ui/dist/assets -File | Sort-Object Length -Descending | Select-Object Name,Length` | jetbrains woff files GONE; no inter files |
| Visual check | `cargo run -- serve` → toggle EN/FA | rendering unchanged |

## Scope

**In scope**:
- `ui/package.json` (remove inter; nothing else) + `ui/package-lock.json`
- `ui/src/app.css` (font imports only)
- `ui/dist/**` (rebuilt — expect net removal of ~130 KB)

**Out of scope** (do NOT touch):
- Any other dependency (lucide, svelte, vite — all fine per the deps audit).
- Font STACKS in `app.css` (which families resolve in which order) — only the
  IMPORTED FILES change. If a stack references Vazirmatn for latin fallback,
  leave it; we only stop SHIPPING the dead files.
- `main.ts`, components.

## Git workflow

- Branch: `advisor/008-font-slimming`
- Commit: `perf(ui): drop dead font payload (inter dep, woff duplicates, vazirmatn latin subsets)`

## Steps

### Step 1: Remove the inter dependency

`cd ui; npm uninstall @fontsource-variable/inter`.

**Verify**: `rg -in "inter" ui/package.json ui/package-lock.json` → no hits
(note: "inter" appears inside words like "internal"/"interface" in lockfile —
check for the package name specifically: `rg -n "fontsource-variable/inter" ui/package-lock.json` → none).

### Step 2: Replace jetbrains-mono generic imports with woff2-only faces

1. Read the Space Grotesk `@font-face` blocks in `app.css` and copy their
   structure exactly (src URL form, `font-display`, unicode-range handling —
   mirror whatever they do).
2. Replace the two `@fontsource/jetbrains-mono/400.css|600.css` imports with
   two `@font-face` blocks for `"JetBrains Mono"` weights 400 and 600,
   `src: url("@fontsource/jetbrains-mono/files/jetbrains-mono-latin-400-normal.woff2") format("woff2")`
   (verify the exact file names inside `ui/node_modules/@fontsource/jetbrains-mono/files/`
   and keep `@fontsource/jetbrains-mono` in package.json — we keep the
   package, just import files directly). Keep the mono font's usage in
   `.mono`/code contexts unchanged.

**Verify**: `npm run build` → `Get-ChildItem ui/dist/assets -Filter "*jetbrains*"` → only `.woff2` files (two), no `.woff`.

### Step 3: Import only Vazirmatn's arabic subset

1. List `ui/node_modules/@fontsource-variable/vazirmatn/*.css` — find the
   arabic-subset entry (e.g. `arabic-wght.css`; names vary — read them).
2. Replace the current vazirmatn import with that subset-only entry.
3. Build and check `ui/dist/assets` for `vazirmatn-*` files: arabic subset
   present, latin/latin-ext gone.

**Verify**: `npm run build` exit 0; size listing shows the drop.

### Step 4: Visual verification (required)

1. `cargo run -- serve` (after build) → open http://127.0.0.1:8765.
2. EN mode: headings, body, mono IP strings render in the same families as
   before (compare against the BEFORE screenshots you take in step 0 — take
   them first!).
3. FA mode (click فا): Persian text renders in Vazirmatn (not a fallback
   system font — compare glyph style with the BEFORE screenshot), RTL layout
   intact.

**Verify**: screenshots before/after attached to the report; FA glyph shapes
identical to before.

## Test plan

- No new unit tests (asset change). `npm run check && npm test` stay green.
- The visual check IS the test — fonts have no DOM-level assertion worth
  automating here.

## Done criteria

- [ ] `rg -n "fontsource-variable/inter" ui/package.json ui/package-lock.json` → no hits
- [ ] `ui/dist/assets` contains no `.woff` (non-woff2) font files and no inter/vazirmatn-latin fonts
- [ ] Net `ui/dist` size reduction ≥ 100 KB (`git diff --stat ui/dist` as evidence)
- [ ] EN and FA rendering visually unchanged (screenshots)
- [ ] `cd ui; npm run check && npm test && npm run build` exit 0; dist committed with src

## STOP conditions

- The arabic-subset-only import changes FA rendering (some punctuation or
  Latin-in-FA strings were silently using Vazirmatn latin) — restore the
  latin subset for vazirmatn and report the finding (the dead-weight estimate
  was wrong for FA contexts).
- The hand-written `@font-face` for jetbrains fails to resolve files at build
  (path/base handling differs from Space Grotesk's) — report the vite error;
  do not switch to inlining fonts as base64.
- `ui/dist` grows instead of shrinking — something re-added payload; report.

## Maintenance notes

- When adding a font family in the future, import subset-specific files
  directly (the Space Grotesk / new JetBrains pattern), never the generic
  package CSS.
- If a future design wants Inter back, re-add it deliberately with subset
  imports.
- Reviewer scrutiny: the FA screenshot comparison is the whole game — merge
  only with the screenshots reviewed.
