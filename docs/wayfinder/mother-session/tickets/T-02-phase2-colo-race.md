# T-02 — phase2-colo-race (F-02)

## Finding
`src/engine/phase2.rs:248-260`: two workers on the same IP — A passes with a
kept colo and stores the verdict; B passes with a rejected colo and calls
`remove_verdict`. If B wins the lock race, the GOOD verdict is deleted.

## Verify
Read `src/engine/phase2.rs` around the colo-check + `update_verdict_phase2` /
`remove_verdict` paths in `src/engine/store.rs`. Reproduce with two fake
tunnel probes returning different colos for the same IP (needs a colo-aware
fake or a unit test on the store sequence).

## Fix
Make removal conditional: only remove if the stored verdict is the rejected
one (compare colo / pass generation; never delete a stored passing verdict
for a rejected-colo latecomer). Simplest sound rule: `remove_verdict` becomes
`remove_verdict_if_colo(ip, rejected_colo)` — no-op when the stored verdict's
colo is kept.

## Test
Regression test: same IP, kept-colo pass lands first, rejected-colo pass
lands second (both orders) → kept verdict survives in both.

## Files
`src/engine/phase2.rs`, `src/engine/store.rs` (+ tests).

## Gates
`cargo test` + `cargo clippy --all-targets -- -D warnings` + `cargo fmt --check`.
