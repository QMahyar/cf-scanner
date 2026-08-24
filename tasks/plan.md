# Implementation Plan: UI v2 — Beginner/Pro modes, i18n+RTL, researched defaults

Evidence base: `docs/research/2026-08-23-ui-v2-research.md` (10 web-verified
research passes). API contract: **unchanged** — every feature maps onto existing
`ScanConfig` fields (verified by audit; bundled ranges already official 15).

## Overview

Rebuild the localhost UI around two explicit modes sharing one engine:
Beginner (Persian-first bilingual, two knobs, top-9 cards, copy/share/download)
and Pro (ranges file import, AWG noise editor, Skip-to-Phase-2, full knobs),
plus research-driven table UX and an RTL-capable visual pass.

## Architecture decisions

- No src/api changes; no new engine behavior. Skip-to-Phase-2 = cancel →
  re-POST with `phase2_only:true` (store retains cancelled-run candidates,
  `engine/cdn.rs` clears only at next full-scan start).
- i18n = tiny `{en,fa}` dictionary module, no dependency; detection
  localStorage `cf-lang` → `navigator.language` fa→fa else en; `html[lang][dir]`
  applied before first paint.
- No new npm deps except possibly the Persian font (user call pending);
  virtualization hand-rolled as a render cap, no TanStack dependency.
- All numbers cited in the research doc; deviations noted inline.

## Task List

### Phase A — Foundations

- [x] T1 (S): `ui/src/lib/i18n.svelte.ts` — dictionary en/fa (~120 keys),
      `$state` locale, `t(key, params)`, detect/persist, `applyDocumentLang()`;
      wire in `main.ts` pre-mount; EN|FA toggle in header.
      AC: toggle flips `<html dir/lang>` instantly and persists across F5;
      `npm run check` green.
- [x] T2 (XS): Persian webfont — pending user pick: (a) add
      `@fontsource-variable/vazirmatn` dep, (b) vendor woff2 in `ui/src/assets`,
      (c) system stack only. Blocks T9 polish, not logic.

### Phase B — Beginner mode

- [x] T3 (M): SimpleStart upgrades — second knob "test up to N candidates"
      (default 800, range 100–10 000, research §2 band); `simpleConfig` switches
      CDN target from `Preset Quick` to `Count(n)`; find-up-to default 10→20
      (research §3, N=10 dominant precedent, midpoint of user's 50 example);
      fa/en copy incl. reassurance line ("takes about a minute… keep tab open");
      export chain copy → `navigator.share` (feature-detected) → Blob `.txt`
      download (research §7).
      AC: both knobs produce expected `ScanConfig` (unit-testable via
      `simpleConfig`); share/download fallbacks typed; check+build green.

### Phase C — Pro additions

- [x] T4 (M): Ranges file import — hidden file input beside Custom CIDRs /
      WARP endpoints; reads one-per-line text; classifies: bare IPv4 → `/32`
      (CDN custom_cidrs) or endpoint line (WARP custom_endpoints); CIDRs pass
      through; merge-dedupe into textarea; count toast. Mirrors existing wgconf
      loader pattern (size cap 256 KB).
      AC: fixture file loads into correct field; invalid lines reported inline;
      no API change.
- [x] T5 (L): AWG noise editor — parse `[Interface]` keys Jc/Jmin/Jmax/S1/S2/
      H1–H4 out of `form.wgconf` (client-side regex; engine's `wgconf.rs`
      AmneziaParams set); structured inputs + Off/Light/Heavy presets
      (research §5 values); validation: Jc 0–128 (0=off), 0≤Jmin<Jmax<1280,
      S1≤1132, S2≤1188, S1+56≠S2, H∈5..2147483647 pairwise distinct non-overlap
      (`N` or `N-M`), reject 1–4; write-back preserves rest of INI verbatim.
      Visible only when wgconf present; keys never persisted (existing
      `persistedFormState` exclusion holds).
      AC: round-trip edit keeps unrelated lines byte-identical; invalid states
      blocked with field errors; unit tests for parse/serialize/validate.
- [x] T6 (M): Skip-to-Phase-2 — ProPanel running state, visible when
      mode=Cdn ∧ phase2On ∧ configs non-empty. Flow: confirm (shows current
      found count; extra confirm if found <5, research §9 guardrails) →
      `api.cancel()` → await not-running → rebuild config with
      `phase2_only:true` → `startScan`. Suggest-only badge: sliding window over
      SSE progress ticks; hint appears when found ≥12 ∧ window success rate
      <3% over last ~500 probes.
      AC: button hidden outside conditions; happy path ends in phase-2 progress
      events; cancel-mid-phase-2 safe; unit test for heuristic function.

### Phase D — Results table UX (research §7)

- [x] T7 (M): ResultsTable upgrades — `<th><button>` sorting with `aria-sort`,
      tri-state asc→desc→none; ≥44 px checkbox hit areas; bulk-copy feedback
      via `role=status` live region; skeleton rows while running∧empty; three
      distinct empty states (pre-scan / filtered-empty / true-zero);
      `dir="ltr"` spans on ip:port + latency tokens; render cap 500 rows with
      explicit "refine filter" note (honest cap, no new dep).
      AC: svelte-check green; keyboard operable; manual mobile check 375px.

### Phase E — Hallmark visual pass

- [x] T8 (M): Typography + rhythm — Vazirmatn (per T2 outcome) with
      `font-display:swap`; line-height 1.7 fa vs 1.5 en; logical-property sweep
      (`ml/mr/pl/pr/text-left/right/left-/right-` → ms/me/ps/pe/start/end);
      mirrored directional icons only (`rtl:scale-x-[-1]`); focus-visible +
      reduced-motion audit; mobile verification 320/375/414/768; dark-token
      palette preserved (pre-flight: oklch token system stays).
      AC: no horizontal scroll at 320px; screenshots at four widths; slop-test
      relevant gates pass; pre-emit critique stamped in CSS comment.

### Checkpoints

- After Phase B: `npm run check && npm run build` green; manual smoke of
  beginner flow via `cargo run -- serve`.
- After Phase D: full `npm run check && npm run build`; cargo suite untouched-
  green (`cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt
  --check`) — proves zero contract drift.
- Final: serve smoke + browser QA (playwright) at 320/768/1280; both locales;
  beginner + pro paths.

## Risks and mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| AWG editor corrupts pasted configs | High | Byte-preserving splice edits + round-trip tests; keys excluded from persistence already |
| Skip flow races (cancel before finished) | Med | Await `running==false` via SSE before resubmitting; disable button while transitioning |
| RTL regressions in dense table | Med | `dir=ltr` data spans; sweep greps; 320px check |
| fa copy quality | Low | Short strings; technical terms kept Latin (ip:port, xray, CIDR) |

## Open questions

- T2 font choice (new dep vs vendored asset vs system stack) — RESOLVED: @fontsource-variable/vazirmatn (user-approved, installed).

---

# Addendum — user feedback + audits (2026-08-23, post-QA)

User reported: bulk ip:port paste leaves blank lines in fields; endpoint/CIDR
validation only surfaces via server round-trip in a generic pill — wants
validate-at-entry gating both scan AND preset save. Two read-only audits
(validation-gap table + UX walkthrough) confirm and extend this.

## Phase F — feedback fixes (this pass)

- [x] T9 (M): `ui/src/lib/validators.ts` — dependency-free line-by-line
      mirror of `src/api/types.rs` + `src/ranges.rs` grammar: parseEndpoint
      (strict v4, opt port 1–65535 ≠0, no v6), parseCidr (strict v4 + v6
      structural, prefix ≤ bits, reject v6 /0, masked canonical form),
      validateSni, validateProbeUrl, isRoutableIpv4, MAX_* constants.
      Wire into buildConfig (kills audit rows 1–21: numeric upper bounds
      count/timeout 100–30000/concurrency/stop/cap/probes, ports ≤64 unique,
      CIDR+exclude syntax/count/routability, endpoints grammar/routability,
      SNI grammar/≤8/≤256B, probeUrl scheme/≤2048B, configs ≤8/≤8KB/`://`,
      wgconf ≤64KB on paste) so scan AND profile save gate identically and
      inline errors light up on touched fields via the existing allIssues
      derivation. importRangesFile re-classifies with the same validators
      (kills rows 22–28: 999.x inserts, /99, port 0/70000, leading zeros,
      dropped v6 CIDRs, uncapped merges).
- [x] T10 (S): paste normalization — `normalizeLines()` (trim, drop blanks,
      dedupe, keep order) applied on blur to customCidrs/exclude/
      warpEndpoints/configsText; blank "first field" can no longer linger.
      Plus quick wins from the UX audit: import button targets its own field
      explicitly (and only shows where valid), mode-flip effect no longer
      wipes restored ports on hydration/profile load, waitForIdle timeout
      surfaces an error, stopScan catches failures, share/download pill gets
      real labels, ETA humanized past 60 s, count input disabled unless
      useCount, dead `custom` fragment option removed, lang button keeps its
      44 px target.

## Deferred (logged, not this pass)

- T11: ProPanel error-model unification (6 channels → field-level + one status
  region), single destructive-action pattern with undo, ranges-import review
  step (pre-merge diff), hoist scan params out of SimpleStart local state,
  hover-only tooltips on touch.
- Contract-drift guard: TS side of the grammar fixture needs a UI test runner
  (vitest = new dep — ask first). Rust side landed 2026-08-23
  (tests/fixtures/grammar-cases.json + ranges/api tests).

## Addendum 2 — live-debug fixes (2026-08-24)

- **UI phase-2 was dead on arrival**: form sent lowercase fragment variants
  (`off`), server serde expects PascalCase (`Off`) → every UI phase-2 start
  422'd into the generic banner. Fixed UI-side: buildConfig maps to wire form,
  formStateFromConfig maps back (old saved profiles keep loading); server
  error router now sends fragment/unknown-variant 400s to the fragment field.
  Verified end-to-end through the UI: candidates verified through xray with
  per-row pass/fail verdicts, no banner.
- **WARP real-keypair verification proven live** with the user's Horror
  AmneziaWG config (8.47.69.81:2408, found @408ms under their private key —
  verify swaps the probe transport, so WARP "found" under verify mode IS the
  verification). UX traps fixed: pasting a wgconf now auto-enables the verify
  checkbox (only file-load did before), and results show a
  "verified with your keypair" badge when the scan ran under the real
  identity (store.lastScanVerified).
- Beginner overshoot ("Find up to 20 → found 70") confirmed as designed
  (stop checks precede dispatch; in-flight probes land) — user chose
  keep-as-is; honest hint added under the knobs.

