# Plan 003: Docs + ADRs + CHANGELOG (review domain docs)

> **Executor instructions**: Follow this plan step by step. This is a
> documentation-only plan. Facts must match the CURRENT code (base commit
> `cd4e3a5`) — read the cited code before writing anything. Report: branch,
> commit hash, and an item-by-item change list. Drift → stop and report.

## Status

- **Priority**: P2 — **Effort**: M — **Risk**: LOW
- **Depends on**: none
- **Category**: docs
- **Planned at**: commit `cd4e3a5`, 2026-08-16

## Why this matters

The docs review found README/spec/AGENTS claims that contradict the code
(build behavior, `#![deny(warnings)]`, WARP receiver-index matching, CI
gates), a stale CHANGELOG, missing ADR trail entries, and a qa-runbook
with WARP/`--ipv6` confusion. Users and CI operators rely on these; wrong
claims cause misdiagnosis.

## Current state (read each before editing)

1. `README.md:107-109` — the "offline builds" bullet claims the GeoIP
   download degrades gracefully offline. **The code hard-fails**: `build.rs`
   downloads the pinned `data/geoip-version.txt` release and verifies its
   SHA-256; any failure (no network, checksum mismatch) FAILS the build
   (ADR-003 documents the pinned+verified design). Rewrite the bullet to
   state: builds require network for the one-time GeoIP download; failure or
   checksum mismatch fails the build; the db is cached afterwards. Do NOT
   change `build.rs`.
2. `docs/qa-runbook.md:46` — a `--ipv6` step sits in the WARP section; the
   CLI rejects `--ipv6` for WARP ("--ipv6 is CDN-only; WARP pools are
   IPv4" — `src/main.rs:259`). Move/remove it.
3. `docs/spec.md:120` — claims a crate-level `#![deny(warnings)]`; the
   repo uses CI `cargo clippy --all-targets -- -D warnings` instead (see
   `.github/workflows/checks.yml`). Fix the claim.
4. `AGENTS.md` "Architecture → WARP probe" — "Response (92B, type 2) or
   Cookie (64B, type 3) + receiver-index match = open". **The code does NOT
   use receiver-index matching** — `src/warp.rs:1-10` documents that
   Cloudflare answers with its own session index and classification is
   shape-only (verified live 2026-08-13). Fix the claim.
5. `docs/README.md` (docs index) — the ADR trail must include ADR-008 and
   ADR-009 (check what's listed vs `docs/decisions/` — add any missing).
6. `docs/spec.md` — "Structure" section: verify `src/engine/` is listed
   (mod.rs + cdn.rs + phase2.rs + warp.rs); add if missing.
7. `CHANGELOG.md` — complete the `[Unreleased]` section. Base it on `git log
   --oneline 0cb4d38..HEAD` PLUS the unmerged review work this cycle:
   cancel handoff across phases, stream re-sync (event-loss recovery),
   WARP validation (preset/cidr rejection), WARP endpoint dedupe,
   sampling fix (>= /24), CDN summary via phase-2 outcome, secret
   redaction (xray stderr, error text), trial-dir drop guards, bundled-xray
   size guard, fragment sockopt gating, reality rejection, vmess
   alterId/security passthrough, persisted server pubkey, 0o600/atomic
   identity writes, and the 2026-08-13 review batch already in
   `0cb4d38`'s message (verify it's already covered). Write for users:
   grouped, plain language, no internal jargon. Do NOT write the 0.4.0
   release section — the integrator bumps the version later.
8. `docs/release-process.md` — the claim "the same gates as checks.yml"
   is wrong: the release workflow's `gate` job is separate (see
   `.github/workflows/release.yml`). Also add a "prepare release" step to
   the flow (version bump + CHANGELOG release section + local gates), and
   note the attestations/`id-token: write` requirement if absent.
9. `docs/development.md` — verify the dist smoke-test + placeholder-restore
   instructions match AGENTS.md's commands (`dist build --artifacts=local`
   then `git restore data/bundled/xray data/bundled/xray.exe`). Add the
   macOS note if missing: `build.rs`/`xray.rs` still map macOS assets but
   macOS support was dropped (ADR-009) — the mappings are dead code;
   README/spec must not promise macOS binaries.
10. New `docs/decisions/ADR-010.md` — API hardening decision. Content:
    no auth token (localhost-only service); `/api/warp/register`
    rate-limited (1/60 s); existing identity refuses overwrite without
    `overwrite:true`; API rejects non-routable custom ranges/endpoints
    (loopback, link-local, unspecified, RFC1918, ULA), CLI unrestricted.
    Status: accepted. Links: ADR-005.
11. New `docs/decisions/ADR-011.md` — contract boundary. Amends ADR-005:
    the shared `src/api/types.rs` remains THE API contract (no domain-layer
    refactor); engine returns domain types; server maps domain → API; engine
    types are never serialized directly. In ADR-005, add a status line
    pointing at ADR-011.
12. `tasks/plan.md` — fix the header/stale task references so it reads as a
    completed plan with the review cycle as the current phase (mirror the
    status wording in `tasks/todo.md`; check both files first).
13. `README.md` — update dist commands/tags to the upcoming `v0.4.0` in
    examples (`dist plan --artifacts=all --tag=v0.4.0`), and any "release
    notes" mention that artifacts are only published by CI.

## Commands you will need

| Purpose | Command              | Expected on success |
|---------|----------------------|---------------------|
| Sanity  | `cargo test --lib server` | all pass (untouched code, sanity) |
| Lint    | `cargo clippy --all-targets -- -D warnings` | exit 0 |
| Format  | `cargo fmt --check`  | exit 0              |

## Scope

**In scope**: `README.md`, `CHANGELOG.md`, `AGENTS.md`, `docs/**`
(README.md, spec.md, development.md, release-process.md, qa-runbook.md,
decisions/ADR-005.md status line, NEW decisions/ADR-010.md,
decisions/ADR-011.md), `tasks/plan.md`, `tasks/todo.md`.

**Out of scope**: all of `src/`, `embed/`, `.github/`, `wix/`,
`dist-workspace.toml`, `Cargo.toml` (version bump is the integrator's job),
`plans/` (this directory is maintained by the plan owner).

## Git workflow

- Branch: `review/r5-docs` from `main` (`cd4e3a5`).
- Commit per item group; message style `review: <what>`.
- Do NOT push or merge.

## Steps

1. Fix README offline-builds bullet (item 1).
2. Fix qa-runbook `--ipv6` placement (item 2).
3. Fix spec `#![deny(warnings)]` claim (item 3).
4. Fix AGENTS.md receiver-index claim (item 4) — word it like the code:
   "shape-only classification (Response 92B type 2 / Cookie 64B type 3);
   no receiver-index match (Cloudflare answers with its own session index,
   verified live)".
5. docs/README ADR trail (item 5).
6. spec structure `src/engine/` (item 6).
7. CHANGELOG [Unreleased] (item 7).
8. release-process prepare step + gate truth (item 8).
9. development.md macOS note + dist flow (item 9).
10. ADR-010 (item 10).
11. ADR-011 + ADR-005 status line (item 11).
12. tasks/plan.md header (item 12).
13. README dist examples → v0.4.0 (item 13).

## Test plan

No automated tests for docs. Verification is factual cross-checks:
- Every claim you write can be traced to code (grep for the cited symbols).
- `grep -rn "deny(warnings)" docs/` → no match after step 3.
- `grep -rn "receiver-index" AGENTS.md` → the corrected sentence.
- ADR-010 and ADR-011 exist and follow the format of an existing ADR in
  `docs/decisions/` (read ADR-005 as the template).

## Done criteria

ALL must hold:
- [ ] All 13 items addressed
- [ ] `cargo test --lib server`, `cargo clippy --all-targets -- -D warnings`,
      `cargo fmt --check` all exit 0 (nothing in src/ changed — sanity)
- [ ] `git status` shows only the in-scope doc files modified
- [ ] Two new ADRs exist; ADR-005 has an ADR-011 pointer
- [ ] Commit on `review/r5-docs`; report hash + item list

## STOP conditions

- A cited location doesn't exist (drift).
- You find a doc claim you cannot verify against code — report it instead
  of guessing.
- You feel the need to touch `src/` or `build.rs` (you don't — docs must
  MATCH the code's current hard-fail behavior, not change it).

## Maintenance notes

- After the integrator bumps to 0.4.0, the CHANGELOG [Unreleased] section
  becomes the 0.4.0 release section — the integrator does that move.
- ADR-010's rate limit/overwrite behavior is implemented in plan 001; if
  001's exact numbers change, update the ADR.