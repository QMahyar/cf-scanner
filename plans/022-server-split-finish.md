# Plan 022: Finish the server split — move the 1,830-line test module out of server/mod.rs

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md`.
>
> **Drift check (run first)**: `git diff --stat 51c4711..HEAD -- src/server/`
> This plan assumes plans/015 and 017 may have touched server/mod.rs —
> re-locate the seams below by CONTENT if line numbers shifted.

## Status

- **Priority**: P3
- **Effort**: S–M
- **Risk**: LOW (pure code motion)
- **Depends on**: plans/015, 017 (land their server/mod.rs edits first so this plan moves final code)
- **Category**: tech-debt
- **Planned at**: commit `51c4711`, 2026-08-26

## Why this matters

The "split the 3.2k-line god file" refactor (commit `8d701f9`) stopped
halfway: `src/server/mod.rs` is still 2,629 lines at `51c4711`, of which
lines ~641–2474 (later ~2629) are ONE `mod tests` block — 74% of the file.
Production code still bundles four concerns (router+13 handlers, request DTO
structs, validation guards, plus the test mass), and five
`#[allow(unused_imports)]` band-aids (lines ~25, ~35–45) keep imports alive
only for the tests. Every handler edit parses 1.8k lines of test mass; the
band-aids hide which imports are actually live.

## Current state

At `51c4711`:

- `src/server/mod.rs:641` — `mod tests {` runs to EOF (97 `#[test]` fns).
- Production region (lines 1–639): `router_with_dir` (~80) with 13 handlers
  (~172–636); request DTOs (`RegisterRequest` ~316, `ExportConfigRequest`
  ~390, `StatusPayload` ~446, others); validation guards
  (`reject_default_warp_ports` ~222, `reject_non_routable` ~234,
  `sanitize_config` ~541, `validate_profile_name` ~620) — NOTE: plan 017
  may have moved the first two into api/types.rs; re-check.
- `#[allow(unused_imports)]` at ~25 and ~35–45 on module re-imports kept
  for tests.
- Siblings already split: `state.rs`, `error.rs`, `guard.rs`, `sse.rs` —
  the file-layout convention is `src/server/<concern>.rs` with `mod`
  declarations in `mod.rs` (read the current `mod` block).
- Test harness helpers live INSIDE the test module (`serve_with_registrar`
  ~729-783, raw-TCP request helpers ~706).

## Commands you will need

| Purpose | Command | Expected |
|---|---|---|
| Full gates | `cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check` | exit 0 |
| Server tests | `cargo test server` | same count of tests as before the move |
| Line counts | `Get-Content src/server/mod.rs | Measure-Object -Line` | ~640 or fewer |

## Scope

**In scope**:
- `src/server/mod.rs` (shrinks)
- NEW: `src/server/tests.rs` (the moved test module)
- Optionally NEW: `src/server/dto.rs` (request DTOs) — only if trivial

**Out of scope** (do NOT touch):
- Handler LOGIC (no edits, only motion)
- `state.rs`, `error.rs`, `guard.rs`, `sse.rs`
- `src/api/**`

## Git workflow

- Branch: `advisor/022-server-split`
- Commits: `refactor(server): move the test module to server/tests.rs`, `refactor(server): drop imports kept alive only for tests` (second commit only if the allows come out cleanly)

## Steps

### Step 1: Move the test module

1. Create `src/server/tests.rs`; cut the entire `mod tests { ... }` block
   (from `mod tests {` at ~641 to the file's final `}`) into it, DEDENTED
   one level (the `mod tests {` wrapper becomes the file itself; keep the
   inner `use super::*;` etc. — read the block's first lines and preserve
   its imports).
2. In `mod.rs` replace the block with:
   ```rust
   #[cfg(test)]
   mod tests;
   ```

**Verify**: `cargo test server` → SAME test count as before the move (count
first: `cargo test server 2>&1 | Select-String "test result"`); full gates
green.

### Step 2: Clean the import band-aids

1. Remove each `#[allow(unused_imports)]` (at ~25, ~35–45) one at a time;
   after each removal run `cargo check` — if the import is genuinely unused
   in production code, delete it; if production uses it, keep it WITHOUT the
   allow.
2. In `src/server/tests.rs`, ensure every import the tests need is present
   (the moved block's `use super::*` covers most; add missing ones until
   `cargo test server` is green).

**Verify**: `rg -n "allow\(unused_imports\)" src/server/` → no hits; full
gates green.

### Step 3 (optional, only if clean): Extract DTOs

If `RegisterRequest`, `ExportConfigRequest`, `StatusPayload`, and friends
form a clean cut (they are pure `#[derive(Serialize, Deserialize)]`
structs), move them to `src/server/dto.rs` with
`pub(crate)` visibility as needed, re-exporting from mod.rs if handlers
reference them unqualified. SKIP if any DTO is entangled with handler
private helpers.

**Verify**: gates green; `git diff` shows pure motion.

## Done criteria

- [ ] `src/server/mod.rs` ≤ ~640 lines; `src/server/tests.rs` holds the full suite
- [ ] Test count unchanged (record the count in the report)
- [ ] No `#[allow(unused_imports)]` left in `src/server/`
- [ ] Full `cargo test` + clippy + fmt green; diff is motion-only (`git diff -w --stat` sanity)

## STOP conditions

- The test block references PRIVATE production items (fns/fields not
  `pub(crate)`) that become unreachable from a sibling file — make them
  `pub(crate)` (minimum visibility change) and note each; if any would need
  `pub`, STOP and report instead.
- Test count changes after the move — something was lost in the cut; revert
  and redo carefully.
- Plan 017's guards are still in the production region in a state that
  contradicts this plan's excerpts — re-locate by content; if the guards'
  ownership is ambiguous, STOP and report rather than guessing.

## Maintenance notes

- New server tests go in `src/server/tests.rs` — keep mod.rs production-only.
- The optional DTO extraction (Step 3) is deliberately skippable; if
  skipped, note it for plan 023's api/types work to consider.
- Reviewer scrutiny: `git diff` must show zero logic edits — review with
  whitespace-insensitivity ON to confirm.
