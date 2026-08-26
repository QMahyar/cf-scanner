# Plan 020: Add clone-free store accessors; stop deep-cloning verdicts for boolean checks and re-syncs

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md`.
>
> **Drift check (run first)**: `git diff --stat 51c4711..HEAD -- src/engine/mod.rs src/server/mod.rs`
> On mismatch with the excerpts below, STOP.

## Status

- **Priority**: P2
- **Effort**: S
- **Risk**: LOW (additive methods; call-site swaps are mechanical)
- **Depends on**: none
- **Category**: perf
- **Planned at**: commit `51c4711`, 2026-08-26

## Why this matters

`ScanController::results()` (`src/engine/mod.rs:125-128`) lazy-sorts then
`.clone()`s the ENTIRE verdict store on every call. A Verdict with its
`Option<String>` country/colo and nested `Phase2Verdict` costs roughly
200–400 B heap-inclusive; a 20k-row scan means a 4–8 MB deep clone per call —
and it happens on:
- every `/api/status` hit, which only needs `is_empty()`
  (`src/server/mod.rs:461`),
- every SSE `Lagged` re-sync DURING a running scan (`src/engine/mod.rs:315-328`,
  the `drive_run` Lagged branch), plus the Finished branches (~288, ~302).

Each clone holds the store mutex while sorting and copying — contending with
the hot flush path. The fix is two clone-free accessors; `/api/results`
stays the one legitimate full-snapshot caller.

## Current state

- `src/engine/mod.rs:124-128` (verified):
  ```rust
  /// Snapshot of the last scan's working endpoints, sorted by latency.
  pub fn results(&self) -> Vec<Verdict> {
      sort_if_dirty(&self.store, &self.store_dirty);
      self.store.lock().unwrap_or_else(|e| e.into_inner()).clone()
  }
  ```
- `src/server/mod.rs:461` — `status_handler`: `state.controller.results().is_empty()`
  (read the exact line; it may be `.results().is_empty()` or assigned then
  checked).
- `src/engine/mod.rs:272-328` — `drive_run`: Lagged branch calls
  `self.results()` to replay verdicts to the recovered consumer; Finished
  branches similar (read the exact call sites).
- Invariant to respect (AGENTS.md): sorted order comes ONLY from
  `results()`/`sort_if_dirty` — never read the raw store expecting sorted
  order. The new accessors must sort first (or delegate to the same
  sort_if_dirty call) before iterating.

## Commands you will need

| Purpose | Command | Expected |
|---|---|---|
| Full gates | `cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check` | exit 0 |
| Targeted | `cargo test engine server` | all pass incl. new |

## Scope

**In scope**:
- `src/engine/mod.rs` (two new methods + drive_run call sites)
- `src/server/mod.rs` (status_handler swap)
- Test modules in engine/mod.rs

**Out of scope** (do NOT touch):
- `results()` itself (public API; `/api/results` and CLI still use it)
- The verdict store's push/flush mechanics
- SSE event shapes

## Git workflow

- Branch: `advisor/020-store-accessors`
- Commit: `perf(engine): clone-free has_results and for_each_result accessors`

## Steps

### Step 1: Add the accessors

In `ScanController`:

```rust
/// True once the last scan produced at least one working endpoint.
pub fn has_results(&self) -> bool {
    sort_if_dirty(&self.store, &self.store_dirty);
    !self.store.lock().unwrap_or_else(|e| e.into_inner()).is_empty()
}

/// Iterate sorted results under the lock without cloning the store.
pub fn for_each_result(&self, mut f: impl FnMut(&Verdict)) {
    sort_if_dirty(&self.store, &self.store_dirty);
    let store = self.store.lock().unwrap_or_else(|e| e.into_inner());
    for v in store.iter() { f(v); }
}
```

(Adapt to the actual field names/lock types — read the struct; `store` may
be `Mutex<Vec<Verdict>>` and `sort_if_dirty` may take different args — mirror
`results()`'s own body.)

**Verify**: `cargo test engine` green (no behavior change yet).

### Step 2: Swap the call sites

1. `src/server/mod.rs:461` (status handler): replace
   `results().is_empty()` with `has_results()` — check whether the handler
   needs the COUNT too (read the StatusPayload; if it has a count field,
   add `result_count()` the same way OR keep one clone there — prefer a
   `result_count()` accessor: `store.lock().len()` after sort_if_dirty).
2. `drive_run` Lagged branch (~315-328): replace `self.results()` iteration
   with `self.for_each_result(|v| { ...emit... })` — CAREFUL: emitting
   inside the callback while holding the store lock means the broadcast
   send happens under the lock. Read the current code: if it clones first
   and emits AFTER dropping the lock, then either (a) accept emit-under-
   lock ONLY if the channel send is non-blocking (broadcast `send` is
   synchronous and never awaits — it is fine), or (b) collect REFERENCES is
   impossible; so (a). Verify `broadcast::Sender::send` is what's used and
   it does not await.

**Verify**: `cargo test engine server` green — the existing
`run_streaming_recovers_verdicts_an_overflowing_consumer_dropped` test
(`mod.rs:824-854`) is the regression net for the Lagged path; it must pass
unchanged.

### Step 3: Test

Add `results_accessors_avoid_full_clone` — hard to assert "no clone"
directly; instead assert semantics: seed the store (via the existing test
helpers), call `has_results()` (true/false cases), and `for_each_result`
collecting (ip, port) pairs — assert sorted order identical to
`results()`'s output for the same seed.

**Verify**: test passes; full gates green.

## Done criteria

- [ ] `rg -n "\.results\(\)" src/server/mod.rs src/engine/mod.rs` → only `/api/results`-path and Finished-snapshot call sites remain (read each remaining hit and confirm it needs the full Vec)
- [ ] status handler uses `has_results`/`result_count`
- [ ] New accessor test passes; Lagged recovery test unchanged and green
- [ ] Full gates green; no out-of-scope files

## STOP conditions

- The Lagged branch needs OWNED verdicts (e.g. it moves them into an event)
  rather than references — report the exact usage; add a
  `clone_result(index)` accessor instead of reverting to full-store clone.
- `status_handler` turns out to need more than emptiness/count (e.g. the
  full summary) — implement exactly what it needs as accessors; if it
  genuinely needs everything, leave it and note that `/api/status` is a
  full-snapshot caller by necessity.

## Maintenance notes

- New "read the store" code must pick: `results()` (needs owned snapshot),
  `has_results`/`result_count` (cheap checks), or `for_each_result`
  (iteration). The doc comments should make this obvious — improve them if
  unclear.
- Reviewer scrutiny: confirm emit-under-lock in drive_run is bounded (the
  callback must not call back into the controller).
