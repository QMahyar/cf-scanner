# Plan 012: Serialize progress emission and honor cancel during phase-2 parsing

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md`.
>
> **Drift check (run first)**: `git diff --stat 51c4711..HEAD -- src/engine/cdn.rs src/engine/warp.rs src/engine/phase2.rs src/engine/mod.rs`
> On mismatch with the excerpts below, STOP.

## Status

- **Priority**: P2
- **Effort**: S–M
- **Risk**: LOW (throttle/dedupe only; verdict accounting untouched)
- **Depends on**: none
- **Category**: bug
- **Planned at**: commit `51c4711`, 2026-08-26

## Why this matters

Two engine-correctness issues visible to every client:

1. **Progress events skip, duplicate, and regress.** Each worker independently
   reads the shared `scanned` counter and emits when `scanned % cadence == 0`
   (`src/engine/cdn.rs:184-187`, `src/engine/warp.rs:183-186`). Concurrent
   completions mean multiples get skipped (counter jumps 49→51) or emitted
   twice, and broadcast delivers out of completion order (1000 before 500).
   `phase2.rs:180-184` has the same pattern, and `phase2.rs:192-200` can emit
   a SECOND terminal `Phase2Progress` when a worker already sent
   `done == total`. UI/SSE consumers see progress going backwards or stalling.
2. **Cancel is ignored during phase-2 config parsing.** `phase2.rs:34` runs
   `parse_phase2_configs(p2).await?` — including live subscription fetches
   (~238-243) — BEFORE the first cancellation check (~97). Cancelling
   mid-scan waits for up to 64 sequential subscription downloads.

Invariants to preserve (from `AGENTS.md` v0.8.0 list): cancellation races
in-flight probes via `tokio::select!` + `ProbeContext::cancelled()`; verdict
store push semantics; event broadcast capacity 4096. This plan changes WHEN
progress events fire, not the store or dispatch.

## Current state

- `src/engine/cdn.rs:184-187` and `src/engine/warp.rs:183-186` (read both):
  worker loop tail does roughly:
  ```rust
  let scanned = scanned_counter.fetch_add(1, Ordering::Relaxed) + 1;
  if scanned % cadence == 0 { emit Progress { scanned, ... } }
  ```
  (exact shape may differ — read it).
- `src/engine/phase2.rs:180-200` — same modulo emission; terminal-emit guard
  around `done == total` allows a duplicate.
- `src/engine/phase2.rs:34` — `parse_phase2_configs(p2).await?` before any
  cancel check; workers check `cancel` from ~97 on.
- `src/engine/mod.rs:272-292` — `drive_run` tail reconciliation can deliver
  `Result` events after the consumer saw `Finished` (streaming path). Fixing
  that ordering is OPTIONAL here (see Step 4 — attempt only if trivial);
  the milestone fix is the priority.
- The engine emits events through a `tokio::sync::broadcast` channel
  (capacity 4096 at `src/engine/mod.rs:82`).

Conventions: `AtomicU64` counters already in scope; no comments unless WHY;
tests use `FakeTransport` scripting (`src/engine/mod.rs:589-621`) — follow it.

## Commands you will need

| Purpose | Command | Expected |
|---|---|---|
| Engine tests | `cargo test engine` | all pass incl. new |
| Full gates | `cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check` | exit 0 |

## Scope

**In scope**:
- `src/engine/cdn.rs`, `src/engine/warp.rs`, `src/engine/phase2.rs`
- `src/engine/mod.rs` (only if the shared helper lands there, and the
  optional Step 4 tail tweak)
- Test modules in those files

**Out of scope** (do NOT touch):
- Dispatch (`i % concurrency` channels), verdict store, `results()`
- SSE server code (`src/server/`)
- Event TYPES in `src/api/types.rs` (no contract change)

## Git workflow

- Branch: `advisor/012-progress-cancel`
- Commits: `fix(engine): emit progress milestones exactly once, in order`, `fix(engine): check cancel during phase-2 config parsing`

## Steps

### Step 1: Milestone emission via a shared last-emitted tracker

Add to the shared scan state (where `scanned` lives — an `AtomicU64`):
`last_emitted_milestone: AtomicU64`. Replace the modulo emission in cdn.rs,
warp.rs, and phase2.rs with:

```rust
let scanned = scanned_counter.fetch_add(1, Ordering::Relaxed) + 1;
let milestone = scanned / cadence;
let prev = last_emitted_milestone.load(Ordering::Relaxed);
if milestone > prev
    && last_emitted_milestone
        .compare_exchange(prev, milestone, Ordering::Relaxed, Ordering::Relaxed)
        .is_ok()
{
    emit Progress { scanned, ... };   // scanned may exceed milestone*cadence slightly; that's fine
}
```

Exactly one worker wins each milestone; milestones fire strictly increasing;
no skips (the winner emits for whatever `scanned` it observed — UI shows
monotonic progress). Extract this into one small helper fn (in
`src/engine/mod.rs` or a shared module) used by all three sites so the
pattern exists once.

**Verify**: `cargo test engine` green; new test (Step 3).

### Step 2: De-duplicate the phase-2 terminal progress

In `phase2.rs`, guard the final `Phase2Progress` emit (~192-200) with the
same last-emitted tracker (or a simple `AtomicBool terminal_sent`):
whichever worker emits `done == total` first sets it; the post-loop emit is
suppressed if set.

**Verify**: `cargo test phase2` green; existing phase-2 tests that assert a
terminal progress still see exactly one.

### Step 3: Tests

Mirror `FakeTransport` scripting (`src/engine/mod.rs:589-621` — read it):

1. `progress_milestones_are_monotonic_and_unique` — run a CDN scan (fake
   transport, ~50 items, cadence 10) collecting Progress events from the
   stream; assert scanned values are strictly increasing and each
   milestone value appears at most once.
2. `phase2_terminal_progress_emitted_once` — scripted phase-2 run; count
   `done == total` Phase2Progress events === 1.
3. `cancel_during_config_parse_aborts_promptly` (Step 4): start a phase-2
   scan whose config includes a subscription URL pointed at a
   never-resolving endpoint (the fake HTTP seam — read how phase-2 tests
   fake fetches today; if there is no seam, use a URL that fails fast
   instead and assert cancel is checked between entries); fire cancel
   almost immediately; assert the run finishes (with a cancelled summary)
   without waiting for all entries.

### Step 4: Cancel-aware config parsing

Thread the cancellation signal into `parse_phase2_configs`:
- Read how `ProbeContext::cancelled()` / the `watch::Receiver` reaches
  workers (`phase2.rs:97`) and pass the SAME signal into
  `parse_phase2_configs` (parameter: `cancel: &watch::Receiver<bool>` or the
  existing context type).
- Inside the entry loop (the `for` over config entries at ~238-243), check
  the signal before each entry's fetch/parse; on cancel, return early with a
  distinguishable outcome (e.g. `Ok(partial)` + flag, or a typed variant the
  caller maps to the normal cancelled-summary path — read how a cancelled
  run currently summarizes and reuse it; do NOT invent a new error string
  that would surface to users).

**Verify**: test 3 above passes; `cargo test` full suite green.

### Step 5 (optional, only if trivial): tail reconciliation ordering

Read `src/engine/mod.rs:272-292`. If preventing post-`Finished` `Result`
events is a small change (e.g. stop draining after the terminal event is
seen by the drive loop), do it; otherwise SKIP and note it as deferred —
do not restructure the streaming path in this plan.

**Verify**: existing streaming tests (`run_streaming_recovers_verdicts...`
at `mod.rs:824-854`) stay green.

## Done criteria

- [ ] One shared milestone-emission helper exists; all three emission sites use it
- [ ] New tests 1–3 pass; full suite green
- [ ] `rg -n "% cadence" src/engine` shows only the helper (or nothing)
- [ ] Cancel during phase-2 parse no longer waits on remaining subscription fetches (test proves)
- [ ] clippy `-D warnings` + fmt clean

## STOP conditions

- The emission sites' actual code differs materially (e.g. cadence computed
  per-phase with different types) such that the shared helper doesn't fit —
  report the real shapes; implement per-file with the same
  compare_exchange pattern rather than forcing one helper.
- There is no existing seam to fake subscription fetches in phase-2 tests —
  implement test 3 with the fail-fast URL variant; if that's also impossible,
  report and ship Steps 1–2 only.
- The cancel-signal type can't be threaded without changing
  `parse_phase2_configs`'s public shape used elsewhere — report call sites.

## Maintenance notes

- The milestone helper is now the ONLY way to emit progress — new probe loops
  must use it, not raw modulo checks.
- The post-Finished Result ordering (Step 5) is explicitly deferred; if SSE
  clients ever misbehave on it, revisit with a dedicated plan.
- Reviewer scrutiny: confirm `Ordering::Relaxed` is sufficient (it is —
  milestone uniqueness only needs the CAS; no data is published via these
  atomics) — but verify no reviewer-requested upgrade to Acquire/Release
  breaks perf assumptions.
