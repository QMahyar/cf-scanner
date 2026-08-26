# Plan 024: Split ranges.rs into pool, http, and official-list modules behind a facade

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md`.
>
> **Drift check (run first)**: `git diff --stat 51c4711..HEAD -- src/ranges.rs src/xray.rs`
> On mismatch with the excerpts below, STOP. Note: plans/015 and 016 edit
> ranges.rs — land them first or re-locate seams by content.

## Status

- **Priority**: P3
- **Effort**: M
- **Risk**: LOW–MED (moving `HTTP_CLIENT` touches 2 consumer files; the
  timeout-per-call-site invariant must be re-verified)
- **Depends on**: plans/015, 016 (their ranges.rs edits land first)
- **Category**: tech-debt
- **Planned at**: commit `51c4711`, 2026-08-26

## Why this matters

`src/ranges.rs` (1,459+ lines) mixes five concerns in one namespace: CIDR
type + pool algebra (pure math), disk persistence of refreshed pools,
RFC3339/time utils, the security-critical shared HTTP client with its
per-hop SSRF guard, and the official-list fetch protocol. The guard —
which xray downloads and subscriptions must not bypass (an AGENTS.md
invariant) — is buried mid-file among pure math; the highest-churn pool
edits touch network code and vice versa. `src/xray.rs:676` reaches into
`ranges::HTTP_CLIENT` directly, so the coupling is real, not hypothetical.

## Current state

At `51c4711` (adjust for 015/016):

- CIDR/pool: `parse_cidr` (~113), `subtract` (~235), `decompose` (~261),
  `CidrPool` (~174) + bundled pool data.
- Persistence: `write_pool_to` (~402), `last_updated_of` (~417).
- Time utils: `rfc3339_utc` (~435), `unix_now` (~425).
- HTTP: `static HTTP_CLIENT` (~23 with the redirect Policy calling
  `validate_fetch_url`), `validate_fetch_url` (~614), `fetch_tls*`
  (~540–592), `HttpGet` seam.
- Official lists: `fetch_official` (~378), `parse_official` (~489),
  `refresh_to_disk` (~386).
- External consumer: `src/xray.rs:676` uses `ranges::HTTP_CLIENT` (grep
  `ranges::` across src/ for the full consumer list before starting).
- Tests: `ranges.rs` has an extensive test module (~918–1346+: plan/presets/
  CIDR sampling tests per the TST audit) + the fetch-guard table (~691–704).

## Commands you will need

| Purpose | Command | Expected |
|---|---|---|
| Full gates | `cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check` | exit 0 |
| Ranges tests | `cargo test ranges` | same test count |

## Scope

**In scope**:
- `src/ranges.rs` → becomes `src/ranges/mod.rs` (facade) plus NEW
  `src/ranges/pool.rs`, `src/ranges/http.rs`, `src/ranges/official.rs`
  (persistence + time utils fold into pool.rs or official.rs — see steps)
- `src/xray.rs` (ONLY the `ranges::HTTP_CLIENT` import path, if it changes)
- Any other consumer's import line (grep first; expect ≤2 files)

**Out of scope** (do NOT touch):
- Guard LOGIC (plan 015 owns the mapped-v6 fix), cap VALUES (plan 016)
- `src/api/**`
- Test BODIES (motion only)

## Git workflow

- Branch: `advisor/024-ranges-split`
- Commits: `refactor(ranges): split into pool/http/official modules behind the ranges facade`

## Steps

### Step 1: Create the module directory

1. `mkdir src/ranges` — move current `ranges.rs` content into
   `src/ranges/mod.rs` temporarily (Rust 2018+ path: `ranges/mod.rs`
   replaces `ranges.rs`; delete the old file).
2. Verify `cargo check` green with everything still in mod.rs.

### Step 2: Cut out the three submodules

1. `src/ranges/http.rs`: `HTTP_CLIENT`, the redirect policy +
   `validate_fetch_url`, `fetch_tls*`, `HttpGet`, `MAX_BODY_BYTES` (and
   plan 016's streaming cap if landed). `pub(crate)` visibility matching
   today's.
2. `src/ranges/pool.rs`: CIDR type, `parse_cidr`, `subtract`, `decompose`,
   `CidrPool`, bundled pools, persistence fns, time utils.
3. `src/ranges/official.rs`: `fetch_official`, `parse_official`,
   `refresh_to_disk` (imports from pool.rs + http.rs).
4. `mod.rs` becomes: `mod pool; pub use pool::*;` (or targeted re-exports —
   match the facade style of plan 023), same for http/official, keeping
   EVERY existing `ranges::*` path alive.

**Verify**: `cargo check --all-targets` exit 0; `git status` shows only
`src/ranges/` + the ≤2 consumer import lines (xray.rs et al.).

### Step 3: Move the tests

Split the test module alongside its subjects: CIDR/sampling tests →
`pool.rs` (or `src/ranges/pool_tests.rs` via #[path], mirroring plan 023's
choice); fetch-guard table → `http.rs`; official-list tests →
`official.rs`. Keep test COUNT identical (record before/after).

**Verify**: `cargo test ranges` → same count; full gates green.

### Step 4: Verify the HTTP_CLIENT invariant

Read every remaining `HTTP_CLIENT` user (xray.rs + any other) and confirm
each call site still sets its own `.timeout(...)` (AGENTS.md invariant —
the client has NO global timeout by design). This is a VERIFICATION step,
not a change step; if a call site lacks a timeout, STOP and report (that's
a live bug the split must not paper over).

**Verify**: report lists each `HTTP_CLIENT` call site with its timeout.

## Done criteria

- [ ] `src/ranges/` is a directory module: mod.rs facade + pool.rs + http.rs + official.rs
- [ ] All `ranges::*` paths unchanged for consumers (`cargo check` + zero consumer edits beyond imports)
- [ ] Test count unchanged; full gates green
- [ ] HTTP_CLIENT call-site timeout audit recorded in the report

## STOP conditions

- A consumer uses a `ranges::` item whose visibility can't be preserved by
  re-exports (private item reached from outside) — report; minimum
  `pub(crate)` widening allowed with a note.
- The static `HTTP_CLIENT`'s `Lazy`/`OnceLock` initialization references
  items that create a module CYCLE between http.rs and pool.rs — break with
  re-exports; if a true cycle exists, report the dependency.
- Any test is lost or renamed in the move — revert and redo.

## Maintenance notes

- New fetch paths MUST go through `ranges::http`'s guarded client — the
  module boundary now makes the invariant visible in the file layout.
- plan 026 (HTTP parser consolidation) will add a `read_response` helper —
  its natural home will be `ranges/http.rs` or socks.rs; decide then.
- Reviewer scrutiny: motion-only diff (`git diff -w` empty for moved
  regions); the xray.rs import line is the only allowed external edit.
