# Plan 025: Consolidate the Rust grammar — one CIDR/endpoint parser behind api::types

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md`.
>
> **Drift check (run first)**: `git diff --stat 51c4711..HEAD -- src/api/ src/ranges/ src/engine/warp.rs src/cli_wizard.rs tests/fixtures/grammar-cases.json`
> This plan assumes plans/017 (guards in validate()) and 023 (api split)
> landed. If not, STOP — the consolidation target moves under your feet.

## Status

- **Priority**: P3
- **Effort**: M
- **Risk**: MED (parsing is security-adjacent — CIDR/endpoints gate what
  gets scanned; careful test porting required)
- **Depends on**: plans/017, 023; benefits from 001 (TS parity test already
  replays the fixture)
- **Category**: tech-debt / migration
- **Planned at**: commit `51c4711`, 2026-08-26

## Why this matters

The finished-product review flagged duplicate CIDR/endpoint parsers as Major
(`docs/review/product-review-2026-08-13.md:184-188`); the v0.7 fix mirrored
the grammar into the UI but left the RUST duplicates standing. Still present
at `51c4711`:

- `src/ranges.rs:113 parse_cidr` vs `src/api/types.rs:611 validate_cidr`
- `src/engine/warp.rs:267 parse_endpoint` vs `src/api/types.rs:662 parse_endpoint`
  / `:695 validate_endpoint`

Two grammars that already disagreed once (the `::/0` incident referenced by
the review) can drift again; every validation change must be made in 2+
Rust places plus the TS mirror. ADR-011's direction makes `api::types` the
contract home — the parsers belong there, with thin re-use elsewhere.

## Current state

- `src/api/types.rs` (or post-023 `src/api/validate.rs`): `validate_cidr`
  (~611), `parse_endpoint` (~662), `validate_endpoint` (~695) — the
  contract-side grammar, consumed by `ScanConfig::validate()`.
- `src/ranges/` (post-024 `pool.rs`): `parse_cidr` — used by pool
  construction, exclusions, plan building (grep `parse_cidr` across src/ for
  every caller; engine/warp.rs and engine/cdn.rs call it).
- `src/engine/warp.rs:267` — `parse_endpoint` for custom WARP endpoints.
- `src/cli_wizard.rs:461-478` — `parse_ports` re-implements port rules that
  `api::types::validate_ports` owns (final `cfg.validate()` catches drift,
  so this is UX-only, but consolidate it too while here).
- Shared fixture: `tests/fixtures/grammar-cases.json` — consumed by Rust
  tests (`src/api/types.rs:~707`) and, since plan 001, by the TS parity
  test.
- The two `parse_cidr` implementations DIFFER in return type at least
  (`Cidr` struct vs whatever validate uses) — read BOTH fully and diff their
  acceptance behavior BEFORE merging; the fixture is the arbiter for
  disagreements (see Step 2).

## Commands you will need

| Purpose | Command | Expected |
|---|---|---|
| Full gates | `cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check` | exit 0 |
| Grammar tests | `cargo test api ranges engine` | all pass incl. ported tests |

## Scope

**In scope**:
- `src/api/validate.rs` (gains the canonical parsers)
- `src/ranges/pool.rs` (parse_cidr becomes a thin wrapper or is replaced)
- `src/engine/warp.rs`, `src/engine/cdn.rs` (call-site swaps only)
- `src/cli_wizard.rs` (parse_ports delegates)
- Test modules in those files + `tests/fixtures/grammar-cases.json` (only
  if a case must be added to pin a resolved disagreement)

**Out of scope** (do NOT touch):
- `ui/src/lib/validators.ts` (the TS mirror stays as-is; plan 001's parity
  test is the guard)
- Acceptance-behavior CHANGES beyond what the fixture adjudicates (any
  input that parsed before must parse after, unless BOTH sides' tests agree
  it was a bug — report such cases)
- `src/server/**`

## Git workflow

- Branch: `advisor/025-grammar-consolidation`
- Commits: `refactor(api): make types the canonical cidr/endpoint grammar`, `refactor(engine): consume the canonical parsers`, `refactor(wizard): delegate port parsing to the shared validator`

## Steps

### Step 1: Diff the two grammars exhaustively

Read both `parse_cidr`s and both `parse_endpoint`s line by line. Build a
behavior table: for each input class (IPv4/IPv6, prefix bounds, host bits
set, mapped-v6, whitespace, zone ids, port ranges), record what EACH
implementation does. Run both against `tests/fixtures/grammar-cases.json`.

**Verify**: the table exists in the report; every disagreement is listed
with which side the fixture agrees with.

### Step 2: Resolve disagreements via the fixture

For each disagreement: the fixture's expected outcome wins. If the fixture
has NO case for it, ADD the case (both sides' most defensible behavior —
usually the STRICTER one, since these gate what gets scanned) to the
fixture, which updates the Rust test AND plan 001's TS parity test in one
motion. If the TS validator then FAILS the new case, that is a real TS
drift bug — fix `validators.ts` too (in scope for exactly this) and note it.

**Verify**: `cargo test api` green with the extended fixture; `cd ui; npm test`
green (parity).

### Step 3: Make api the canonical home

1. In `src/api/validate.rs`, ensure `parse_cidr`-equivalent exists with the
   CANONICAL behavior and returns the data validate() needs (read what
   validate_cidr does today — it may parse-and-discard; expose a
   `parse_cidr` that returns a shared minimal struct OR keep
   validate_cidr calling the canonical parser).
2. `src/ranges/pool.rs`: replace its `parse_cidr` body with a delegation to
   the canonical parser, constructing the pool-side `Cidr` struct from the
   canonical result. Keep the pool-side struct and ALL its tests (they pin
   pool behavior, not grammar).
3. `src/engine/warp.rs:267`: delete the local `parse_endpoint`; call the
   canonical one; adapt the result into what the caller needs.
4. `src/cli_wizard.rs`: `parse_ports` delegates to
   `api::types::validate_ports`' logic (keep the wizard's error TEXT if its
   prompts depend on it — read it).

**Verify**: `cargo test` full suite green. `rg -n "fn parse_cidr|fn parse_endpoint" src/` → ONE implementation each (plus thin delegating wrappers whose bodies are ≤5 lines).

### Step 4: Port the orphaned tests

Move/copy the grammar-acceptance tests from ranges.rs and warp.rs into the
api test module (the POOL tests stay in pool.rs — only grammar tests move).
Where both sides tested the same input with different expectations, the
fixture-pinned expectation stands and the loser's test is updated with a
one-line WHY comment referencing the fixture.

**Verify**: test count ≥ pre-refactor count (record both); full gates green.

## Done criteria

- [ ] One canonical `parse_cidr` and one `parse_endpoint` (plus ≤5-line wrappers)
- [ ] Fixture extended with any newly-pinned cases; TS parity test green
- [ ] Full `cargo test` + clippy + fmt green; test count recorded
- [ ] Wizard delegates port parsing
- [ ] Report contains the Step-1 disagreement table

## STOP conditions

- The two grammars disagree on a SECURITY-RELEVANT class (private/loopback
  acceptance) and the fixture + review cannot settle which is correct —
  STOP and report; do not pick silently.
- The pool-side `Cidr` struct carries invariants the canonical parser's
  output can't satisfy (e.g. normalized host bits) — report the mismatch;
  normalization belongs in the wrapper, but only if both grammars agree on
  normalization.
- Consolidation changes acceptance for an input the UI's TS validator
  accepts and a test pins — that's a three-way disagreement; report it.

## Maintenance notes

- After this lands there is ONE Rust grammar, ONE fixture, and ONE TS
  mirror — grammar changes touch exactly: api/validate.rs + fixture +
  validators.ts (the parity test enforces all three).
- The review item this closes (`product-review:184-188`) can be marked done
  in the next docs pass.
- Reviewer scrutiny: every acceptance CHANGE traces to a fixture case added
  in Step 2 — no drive-by tightening.
