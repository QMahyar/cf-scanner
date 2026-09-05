# SPEC — Mother Session hardening program

Status: PROPOSED (refine gate → APPROVED). Date: 2026-09-05.
Source: `docs/audit/mother-session/FINDINGS.md` (F-01…F-27, C-1…C-6).

## 1. Objective

Fix every confirmed-or-verified finding from the mother-session audit in
impact order — correctness bugs first, architecture paydown last — with zero
regressions (full gates per ticket), zero default-behavior changes unless
explicitly approved below, and zero new dependencies unless a P6 ticket is
explicitly pulled. Output: one PR (`review/mother-session` → `main`) plus an
`[Unreleased]` CHANGELOG entry.

## 2. Scope (by finding ID)

- **P0 correctness (F-01…F-14):** all in scope. Each ticket starts with
  "verify in code" — if the raw finding does not reproduce, the ticket closes
  with evidence instead of a change.
- **P1 validation (F-15, F-16):** in scope. New rejections only for
  currently-meaningless combinations (WARP+neighbor, Tcp+http-codes,
  cap<found); valid configs are unaffected.
- **P2 coverage (F-17, F-18, F-19):** in scope. Offline-only in CI
  (fakes/loopback/temp-dirs); `#[ignore]` live tests stay manual.
- **P3 docs (F-20…F-23):** in scope. README/CLI-help/CHANGELOG/ADR/intent/
  AGENTS/GitHub-meta. Dead-type removal (F-23) is code deletion + clippy proof.
- **P4 export/distribution (F-24, F-25, F-26):** in scope EXCEPT output-shape
  changes to existing formats (refine gate §7). New formats are new
  `--export-format` values (additive). Release-pipeline edits are config-only.
- **P5 architecture (F-27.1…F-27.7):** in scope, mechanical refactors with
  behavior-preservation proof (tests green + `git diff` review per ticket).
  No perf-infra (no benches); micros only where the win is structural
  (Arc/clone removal), never speculative.
- **P6 capabilities (C-1…C-6):** proposals. C-1 (sub validation), C-2
  (docs-first refresh), C-4 (IPv6 pass), C-5 (live CI job), C-6 (Termux docs)
  are pre-approved in principle, pending refine. C-3 (QUIC/DoH/Trojan-Go)
  needs explicit pull (new deps).

## 3. Non-goals (see FINDINGS "Explicitly NOT doing")
macOS targets · Stash export · `--quiet` · transport middleware ·
`step_budgets` flag · default speed tests · version bump/tag/publish.

## 4. Contract & compatibility rules
- Valid scan configs keep working; NDJSON/event schema unchanged; existing
  `--export-format` outputs byte-identical unless §7 approves otherwise.
- New `ScanConfig`/`Phase2Config`/`WarpConfig` fields (none planned) would need
  `#[serde(default)]` per the v0.8.0 invariant.
- `--retry-last` files written by older versions must still load (F-07).

## 5. Testing rules
- Every behavior ticket ships a regression test that FAILS before the fix
  (verify-then-fix; if it already passes, the finding is closed as
  not-reproduced with evidence).
- No real network in CI tests. No committed binaries/mmdb. S/M tickets (≤5 files).

## 6. Docs rules
- README Commands reference must match `--help` (add a CI grep gate:
  every `long` flag appears in README; every flag has non-empty help text).
- CHANGELOG `[Unreleased]` updated as tickets land.

## 7. Refine gate — DECIDED 2026-09-05 (user approved all recommendations)
1. F-07 serde policy: **tolerant `load_config`** (strip unknown fields / fill
   defaults; strict CLI parsing stays).
2. F-09 `--phase2-only`: **remove** the flag + unreachable engine path.
3. F-11 trial-dir chmod failure: **fail closed** (abort attempt, clear error).
4. F-13 corrupt refresh: **warn + bundled** (exact parse error to stderr).
5. F-24 export shape: **additive only** (existing outputs byte-identical;
   strip `config_index` from JSON export; IPv6 in bundles = loud-drop with
   count + stderr warning; full-config formats deferred to new values).
6. F-23 dead-type deletion: **approved**.
7. P6 pulls: **C-1, C-2, C-4, C-5, C-6 + musl proposal** enter; C-3 (new
   protocols/deps) **deferred**.
8. F-25 musl: **ticket-as-proposal now** (doc-only, no matrix change).
1. F-07 serde policy: tolerant `load_config` vs strict-everywhere?
2. F-09 `--phase2-only`: remove flag+engine path, or keep rejecting?
3. F-11 trial-dir chmod failure: fail closed or warn-and-continue?
4. F-13 corrupt refresh: warn+ mainland bundled, or hard-fail scan?
5. F-24 output shape: new `singbox-full`/`clash-full` values vs in-place change?
   (plus: strip `config_index` from JSON export? IPv6 in bundles: emit or loud-drop?)
6. F-23 dead-type deletion: approved?
7. P6 pulls: which of C-1…C-6 enter this PR? (C-3 needs per-item pull.)
8. F-25 musl proposal: ticket-as-proposal now, or defer?
