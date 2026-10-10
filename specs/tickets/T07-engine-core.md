# T07 — engine core: phase2 lock, store, envelopes, ASN

Spec stories 12, 15-16, 21.

## Goal
- Phase-2 mutex per combo (`src/engine/phase2.rs:121-141,173-194,208-231`).
- Store O(n) + re-sort per read (`src/engine/store.rs`, `src/engine/mod.rs:207-226`).
- `serialize_event` drops rows silently (`src/main.rs:584-592`).
- Double error envelope (`src/engine/mod.rs:418-427` + `src/main.rs:43-47`).
- ASN enriches failures uncached (`src/enrich.rs:81-85`, called `src/main.rs:336-339`).

## Scope
- `src/engine/phase2.rs`, `src/engine/store.rs`, `src/engine/mod.rs`, `src/main.rs`, `src/enrich.rs`.
- Atomic `passed_count` for stop-budget, keep HashSet only for dedup.
- Keep PosIndex across removals (swap-remove + patch) or keyed map + lazy view.
- Count drops + stderr warning; pin single failure envelope.
- Enrich only working endpoints + in-memory IpAddr->AsnInfo cache.

## Acceptance
- Concurrency test for phase-2 stop; store benchmarks or unit tests for remove/update.
- Envelope test: exactly one error shape per failure.
- `cargo test --locked -- engine enrich` green.

## Commands
`cargo test --locked engine`, `cargo test --locked enrich`, `cargo clippy --all-targets --locked -- -D warnings`
