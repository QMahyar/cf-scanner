# T-17 — critical-path-coverage (F-17)

## Gaps (zero-coverage critical paths; offline-only)
1. `src/xray.rs` (CRITICAL): `spawn`, `XrayProcess::stop`,
   `write_trial_config`, `capture_stderr`, `download_binary`,
   `RealFetch::bytes`, `find_entry` error path, `make_executable`.
2. `src/verify.rs` (CRITICAL): `XrayTunnelProbe::probe`,
   `open_tunnel_session`, `RealTunnelOpener::open`, stale-dir sweep CAS,
   `require_xray_binary`, `TunnelSession::cleanup`.
3. `src/socks.rs` (HIGH): `timed_download_via_socks`, `count_download`,
   HTTPS branch, `socks5_connect` addr types + error paths.
4. `src/ranges/http.rs` (MEDIUM): `fetch_tls_with_headers`, `fetch_bytes`,
   `fetch_tls_inner`, `sanitize_url_for_error`, redirect policy.

## Approach (proven patterns — no new infra)
- Fake xray binary: executable shell/batch script in temp dir +
  `CF_SCANNER_DATA_DIR` (extends `tests/xray_lifecycle.rs` pattern).
- SOCKS5: scripted loopback server (extends existing scripted-server tests).
- HTTP fetch: loopback TLS server with `rcgen` (dev-dep already present) or
  plain-HTTP loopback where the code path allows; redirect-policy tests via
  chained loopback servers.
- `#[ignore]` live tests stay manual; CI stays offline.

## Files
`tests/xray_lifecycle.rs`, `src/xray.rs` (test mods), `src/verify.rs`,
`src/socks.rs`, `src/ranges/http.rs` test mods. Split commits per area if big.

## Gates
`cargo test` + `cargo clippy --all-targets -- -D warnings` + `cargo fmt --check`.
