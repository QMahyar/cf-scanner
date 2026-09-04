## Question

How do we extract the shared engine internals (verdict store, neighbor
scanning, lock helper, test fakes) into focused modules without changing
scan behavior?

## Scope

Four related extractions from the 2026-09-06 architecture review:

1. **`engine/store.rs`** (from `mod.rs`): `Store` type alias,
   `snapshot_sorted`, `merge_sorted`, `clear_store`, `PosIndex`,
   `update_verdict_phase2`, `remove_verdict`. Also move `plan_hosts_iter`
   and `plan_probe_count` from `mod.rs` → `plan.rs` (they operate on
   `PlanItem` types).

2. **`engine/neighbor.rs`** (from `cdn.rs`): `NeighborHub`,
   `neighbor_candidates`. Currently tangled in the 230-line `run_cdn`.

3. **Lock helper**: 40+ instances of
   `.lock().unwrap_or_else(|e| e.into_inner())` across `mod.rs`, `cdn.rs`,
   `warp.rs`, `phase2.rs`. Extract `fn lock<T>(m: &Mutex<T>) -> MutexGuard<T>`
   to handle poison recovery in one place.

4. **Shared test helpers**: `FakeSub` duplicated in `phase2.rs` tests (~560)
   and `speed.rs` tests (~230). Extract to `engine/test_helpers.rs`
   (or `#[cfg(test)]` module).

5. **Worker-loop bodies**: `run_cdn` (~230 lines) and `run_warp` (~170 lines)
   each contain 60-80 line inline task bodies. Extract to named async fns.
   `verify_phase` (~180 lines, 14 Arc-wrapped vars) → `Phase2State` struct.

## Acceptance

- [ ] No file in `engine/` exceeds 800 lines (excluding tests)
- [ ] All existing tests pass unchanged (moved, not rewritten)
- [ ] `cargo test` + `cargo clippy --all-targets -- -D warnings` +
      `cargo fmt --check` all pass
- [ ] Scan behavior identical (verify with existing integration tests)

## Boundaries

- Pure refactor — zero behavior change
- Keep v0.8.0 worker-pool architecture intact (per-worker bounded channels,
  `i % concurrency` round-robin, backpressured `send().await`)
- Keep cancellation pattern (`tokio::select!` + `cancelled()`)
- ≤5 files per commit; land as one branch with sequential commits
