# T01 — check-sub concurrent probing (ordered)

Spec: `specs/hardening-spec.md` stories 1-2.

## Goal
`src/check_sub.rs:60-63` probes serially. Add bounded concurrency, preserve input order.

## Scope
- `src/check_sub.rs` `check_subscription` / `check_one`.
- Keep per-config timeout `timeout_ms+1000` semantics (`src/check_sub.rs:111-115`).
- Concurrency cap: reuse existing pattern (enrichment / phase-2 concurrency), default 16, honor cancel if plumbed.
- Rows output in `config_index` order.

## Acceptance
- `cargo test --locked -- check_sub` green.
- New unit test: N configs probe concurrently (record max in-flight >=2) and output order matches input.
- No behavior change for caps (2048), timeouts, error sanitizing.

## Commands
`cargo test --locked check_sub -- --nocapture`, `cargo clippy --all-targets --locked -- -D warnings`, `cargo fmt --check`
