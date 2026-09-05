# T-33 — arch-paydown-7: perf micros (F-27.7)

## Candidates (structural wins only — no speculation, no bench infra)
1. `HttpTransport`: `accepted_codes: Vec<u16>` cloned per probe → `Arc<[u16]>`.
2. `ScanEvent::Result(Box::new(verdict.clone()))` double-clone per hit → single clone.
3. `for_each_result` clones the whole store Vec under lock → iterate under
   lock with a callback (lock scope unchanged semantically) or len+get.
4. `Verdict` hot-path `Option<String>` audit (`fail_reason`, colo?) — only
   change what is provably allocated per-probe vs per-hit.
5. `plan_hosts_iter` Box-per-CIDR → concrete iterator or `impl Iterator`
   (lifetime work; drop if it fights the borrow checker — note it).
6. `snapshot_sorted` sort-under-lock window — MEASURE first (contention only
   matters with concurrent readers mid-scan); document decision.

## Skip (acceptable by design — document in commit, don't touch)
SocketCache TOCTOU, NEXT_INDEX skip-0, `step_budgets`, transport middleware.

## Files
`src/probe.rs`, `src/engine/mod.rs`, `src/engine/store.rs`, `src/api/types.rs`
(as needed; ≤5 files per commit).

## Gates
`cargo test` + `cargo clippy --all-targets -- -D warnings` + `cargo fmt --check`.
