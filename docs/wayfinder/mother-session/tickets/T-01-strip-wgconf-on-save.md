# T-01 — strip-wgconf-on-save (F-01)

## Finding
`save_config` (`src/retry.rs:16-23`) drops only `phase2` but persists
`warp.wgconf` (WireGuard **private key**) to `last-scan.json`, contradicting
the `--retry-last` help text (`src/cli.rs:308-312`): "Phase-2 configs and WARP
keys are never saved". File IS 0600 via `write_secret` (mitigating), but the
promise is violated.

## Verify
Read `src/retry.rs`, `src/cli.rs:300-315`. Confirm `wgconf` survives the
sanitize clone.

## Fix
- In `save_config`, also strip `sanitized.warp.wgconf = None` (and set
  `verify_with_wgconf = false` for consistency — a retry with verify-on but
  no key would fail validation anyway).
- Keep help text as-is (it becomes true).

## Test
- `save_config` with a `wgconf: Some(...)` config → read file → assert no
  `wgconf`/private-key material present, `phase2` absent, rest intact.

## Files
`src/retry.rs` (+ test module or `tests/`).

## Gates
`cargo test` + `cargo clippy --all-targets -- -D warnings` + `cargo fmt --check`.
