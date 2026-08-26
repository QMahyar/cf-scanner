# Plan 023: Split api/types.rs into limits, contract, error, and validate modules behind one facade

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md`.
>
> **Drift check (run first)**: `git diff --stat 51c4711..HEAD -- src/api/`
> This plan touches `src/api/` — per AGENTS.md that is an "ask first"
> boundary. The maintainer has pre-approved THIS SPECIFIC refactor (facade
  preserved, zero public-API change). If anything forces a public change,
> STOP.

## Status

- **Priority**: P3
- **Effort**: M
- **Risk**: LOW (pure re-export shuffle; no call sites change)
- **Depends on**: plans/017 (admission guards land in validate() first, so the split moves final code)
- **Category**: tech-debt
- **Planned at**: commit `51c4711`, 2026-08-26

## Why this matters

`src/api/types.rs` (1,507 lines at `51c4711`) is the single most-imported
module in the repo (engine, server, wizard, xray, warpgen all consume it)
AND the file AGENTS.md marks "ask first" for changes. It is four modules
wearing one file: wire-limit constants (~9–49), the contract structs/enums
(~51–300), the `ConfigError` taxonomy (~302–377), validator functions
(~482–697), plus ~900 lines of tests (~699–EOF). Contract diffs drown in
validator and test noise, making the highest-friction file the hardest to
review incrementally. The fix: split internally, keep `api/types.rs` as the
public facade re-exporting everything — NO call site changes, ADR-011's
consumption pattern untouched.

## Current state

At `51c4711` (re-locate by content if 017 shifted lines):

- `src/api/types.rs` regions: consts `MAX_*` ~9–49; contract structs/enums
  (`ScanConfig`, `Phase2Config`, `WarpConfig`, `Verdict`, `StopCondition`,
  events, `Phase2Verdict`...) ~51–300; `ConfigError` + helpers ~302–377;
  `validate_ports` ~482, `validate_phase2` ~507, `validate_fragment` ~570,
  `validate_cidr` ~611, `validate_sni` ~629, `parse_endpoint` ~662,
  `validate_endpoint` ~695; `#[cfg(test)]` ~699–EOF (~50 tests incl.
  round-trip and deny_unknown_fields; the grammar fixture consumer at ~707).
- `src/api/mod.rs` — 1 line (`pub mod types;` or similar; read it).
- Consumers (do not touch): grep `api::types` / `use crate::api` across
  `src/` to confirm the facade keeps every currently-`pub` path working.
- ADR-011 (`docs/decisions/ADR-011-contract-boundary.md`) — the engine
  consumes api types directly BY DESIGN; this refactor must not introduce
  mapping layers.

## Commands you will need

| Purpose | Command | Expected |
|---|---|---|
| Full gates | `cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check` | exit 0 |
| API tests | `cargo test api` | same test count |
| Consumer sanity | `cargo check --all-targets` | exit 0 with NO consumer-file edits in the diff |

## Scope

**In scope**:
- `src/api/types.rs` (becomes the facade)
- NEW: `src/api/limits.rs`, `src/api/error.rs`, `src/api/validate.rs`,
  `src/api/types/tests.rs` (or `src/api/types_tests.rs` — pick the layout
  that works with the module system; see Step 1)
- `src/api/mod.rs` (new `mod` declarations)

**Out of scope** (do NOT touch):
- ANY other file in the repo — zero consumer edits is a done criterion
- Struct/field/enum DEFINITIONS (motion only, byte-identical bodies)
- Serde attributes, validation RULES, cap VALUES

## Git workflow

- Branch: `advisor/023-api-types-split`
- Commits: `refactor(api): split types.rs into limits/error/validate modules behind the types facade`, `test(api): move the types test module` (or one commit if cleaner — the gate must pass after each)

## Steps

### Step 1: Create the submodules by moving code verbatim

1. `src/api/limits.rs` — the `MAX_*` consts (make them `pub` if not already;
   they are referenced by validate.rs and consumers).
2. `src/api/error.rs` — `ConfigError` and its helpers.
3. `src/api/validate.rs` — the validator/parse fns (`use super::limits::*;`
   as needed).
4. The contract structs/enums stay physically in `types.rs` (they ARE the
   facade's core) — do not move them.
5. Tests: move the `#[cfg(test)] mod tests` block to a sibling file. With
   the structs staying in types.rs, the cleanest layout is:
   `src/api/types.rs` keeps `#[cfg(test)] #[path = "types_tests.rs"] mod tests;`
   with `src/api/types_tests.rs` holding the dedented tests. (Alternative:
   inline `mod tests` stays in types.rs — acceptable if the #[path] trick
   fights the toolchain; prefer the sibling file for the line-count win.)

**Verify**: `cargo check --all-targets` exit 0.

### Step 2: Make types.rs the facade

At the top of `types.rs`:

```rust
mod limits; // if kept private-ish; or pub mod with re-export
pub use limits::*;   // MAX_* constants keep their paths
mod error;
pub use error::*;
mod validate;
pub use validate::*;
```

Adjust visibility so EVERY path that compiled before still compiles
(`api::types::MAX_ENDPOINTS`, `api::types::validate_cidr`,
`api::types::ConfigError`, ...). Grep consumers first
(`rg -n "types::" src/ --type rust`) and confirm each referenced symbol is
re-exported.

**Verify**: `cargo check --all-targets` exit 0 with `git status` showing NO
modified files outside `src/api/`. This is the hard gate.

### Step 3: Tests + gates

`cargo test` full suite (test count unchanged — record it); clippy + fmt
green. Line counts: `types.rs` should now be roughly the contract structs +
facade re-exports (~350–450 lines); `validate.rs` ~250; `error.rs` ~100;
`limits.rs` ~50; `types_tests.rs` ~900.

## Done criteria

- [ ] `src/api/` contains limits.rs, error.rs, validate.rs (+ tests file); types.rs is facade + contract structs
- [ ] `git status` — zero modified files outside `src/api/` (THE done criterion)
- [ ] Test count unchanged; full gates green
- [ ] `rg -n "pub use" src/api/types.rs` shows the re-export block

## STOP conditions

- Any consumer breaks that cannot be fixed by adjusting re-exports (i.e. a
  consumer reached a private item) — report the symbol and consumer; do not
  edit the consumer.
- The `#[path]` test-file trick fails on the pinned toolchain — fall back
  to keeping `mod tests` inline in types.rs and note it.
- Serde attributes would need to change for any split (they shouldn't —
  structs don't move) — report if they appear to.

## Maintenance notes

- New contract fields → types.rs; new validation rules → validate.rs (+ the
  TS mirror per plan 001's parity test); new caps → limits.rs (+ UI mirror
  constants).
- AGENTS.md's "ask first" for `src/api/` still applies — this refactor
  doesn't change that; it just makes reviews readable.
- Reviewer scrutiny: `git diff` on non-api files must be EMPTY; struct
  bodies byte-identical (review with `-w`).
