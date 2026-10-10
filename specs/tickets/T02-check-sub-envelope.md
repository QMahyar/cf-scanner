# T02 — check-sub NDJSON envelope + JSON-safe aggregate

Spec stories 3-4.

## Goal
Aggregate row uses `usize::MAX` (`src/check_sub.rs:67-79`), exceeds JS 2^53. Rows lack `{"type":...}` envelope vs scan (`src/api/types.rs:396-404`).

## Scope
- `src/check_sub.rs` `CheckRow` + serialization in `src/main.rs` check-sub path.
- Use `null` (or -1) for aggregate `config_index`; add `"type":"check_result"` (or `check-sub`) to every row.
- Update CHANGELOG-adjacent docs/help if they pin sentinel `18446744073709551615`.

## Acceptance
- Unit test pins aggregate sentinel JSON-safe + envelope present.
- Existing test `rows_carry_their_config_index` updated.
- `cargo test --locked -- check_sub` green.

## Commands
`cargo test --locked check_sub`, `cargo clippy --all-targets --locked -- -D warnings`
