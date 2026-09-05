# T-15 — validation-rejections (F-15)

## Gaps (all in `src/api/validate.rs` + `src/api/limits.rs`)
1. `neighbor_count > 0` accepted in WARP mode (silent no-op).
2. `probe_mode = Tcp` + non-default `accepted_http_codes` accepted (codes meaningless).
3. `stop.cap < stop.found` silently accepted (nonsensical combination).
4. `validate_ports` allows 4096 raw entries pre-dedup (cap the raw list, then dedupe).
5. `probe_url`/`probe_urls` legacy dual-field coexistence (document precedence; reject neither — compat — but warn? NO warn infra for config; document in help text).
6. CLI↔API duplicate validation drift (share predicates where a 5-line helper kills the drift; no big refactor).

## Verify
Read `validate()` + `validate_ports` + `validate_phase2` + CLI-side checks in
`src/cli/scan_args.rs`. Confirm each gap reproduces (config validates today).

## Fix
Add rejections for (1), (2), (3) with clear `ConfigError` variants + messages;
cap raw ports pre-dedup at the documented limit; document (5) precedence in the
flag help text; extract shared helpers for (6) where trivial.

## Test
Each new rejection gets a `types_tests.rs` case (valid combos still pass —
esp. WARP without neighbor, Tcp without codes, cap>found).

## Files
`src/api/validate.rs`, `src/api/error.rs`, `src/api/limits.rs`,
`src/cli.rs` (help text), `src/api/types_tests.rs`.

## Gates
`cargo test` + `cargo clippy --all-targets -- -D warnings` + `cargo fmt --check`.
