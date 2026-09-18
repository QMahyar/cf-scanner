# 03: SOCKS ServerName repair for IP-literal dials

**What to build:** phase-2 verification against endpoints presenting SNI-based certificates succeeds where it previously failed TLS: one shared hostname-to-ServerName helper (IP-literal fallback + bracket stripping) used by every in-tunnel TLS handshake. Remote DNS resolution behavior is unchanged (already domain-based).

**Blocked by:** None (can start immediately).

**Status:** done

Spec: `../spec-best-in-class.md` §P0-3. Inherits spec §6 execution rules.

- [x] Single shared helper; all three in-tunnel TLS handshake sites use it
- [x] Previously-failing IP-literal-with-SNI-cert dials now verify (regression test with injected transport); previously-passing paths unchanged
- [x] No contract or default change; secrets never reach logs
- [x] `cargo test` + `cargo clippy --all-targets -- -D warnings` + `cargo fmt --check` green

## Result

Done. All work is in `src/socks.rs` + `src/inline_verify.rs` (code + tests);
no other file touched.

**Failure mode (verified by experiment, not assumed):** `Url::host_str`
keeps IPv6 brackets (`https://[::1]/x` -> `"[::1]"`, probed with a scratch
integration test, since removed), and rustls-pki-types 1.15.1
`ServerName::try_from` rejects bracketed input (`Err(InvalidDnsNameError)`).
So every IPv6-literal probe/speed URL failed locally with "invalid hostname" /
"probe host is not a valid TLS name" before any handshake bytes. Bare
IPv4/IPv6 literals already mapped to `IpAddress` via `try_from`; domains were
unaffected.

**Fix:**
- `src/socks.rs: server_name_for_host(&str)` — shared helper: strip `[`/`]`
  exactly like `configs::split_host_port` / `parse_sip002`
  (`trim_start_matches('[').trim_end_matches(']')`), explicit
  `IpAddr` parse -> `ServerName::IpAddress` fallback, else `try_from` for
  DNS. No context attached, so each call site keeps its exact error string.
- Called at all three in-tunnel TLS handshake sites with unchanged messages:
  `timed_download_via_socks_inner` ("invalid hostname"),
  `get_via_socks_inner` ("invalid hostname"),
  `open_live_tunnel` inner handshake in `src/inline_verify.rs`
  ("probe host is not a valid TLS name"). `socks5_connect` ATYP logic
  untouched (remote-resolve behavior unchanged).
- Test seam (no behavior change): both socks.rs inners delegate to
  `*_inner_with(url, socks, connect_tls)` generic over the TLS-handshake
  closure; production passes `real_tls_connect` (shared webpki connector).
  No new trait/object-safety machinery, no new deps.

**Tests (8 new, all offline loopback; no test deleted):**
- `socks.rs`: helper unit tests (IPv4/bare-IPv6 -> `IpAddress`, bracketed
  IPv6 -> `IpAddress` with the old-constructor-fails assertion pinned,
  domains byte-identical to `try_from`, invalid hosts still `Err`); mock-TLS
  (identity-transform) end-to-end through a fake SOCKS server for
  `https://[::1]/...` on both the probe path (body + recorded `IpAddress`
  + ATYP-domain still sent) and the download path, plus a domain control
  (`https://example.test/...` -> recorded `DnsName`, body OK).
- `inline_verify.rs`: `parse_target("https://[::1]/...")` -> `"[::1]"` ->
  shared helper -> `IpAddress`; domain target stays `DnsName`.

**Gate evidence (on a tree where only this ticket's files differed from HEAD
in scope):** `cargo test` all targets green (lib 675 passed / 0 failed;
integration suites 57+16+16+2 passed, 0 failed), `cargo clippy --all-targets
-- -D warnings` clean, `cargo fmt --check` clean (incl. a later per-file
`rustfmt --edition 2024 --check` on both files: exit 0).

**Caveat:** sibling execution tickets are editing the same tree concurrently
(P0-5 `src/warp.rs` arity/`WarpConfig::junk_*`, P0-7 `src/cli_wizard.rs`);
at close-out `cargo check` reports only their E0061/E0063 errors and zero
diagnostics in `socks.rs`/`inline_verify.rs`. Whole-tree gates should be
re-run once siblings land. `rust-engineering` skill was unavailable in this
session; proceeded per spec §6 + AGENTS.md invariants (verified by direct
reads).
