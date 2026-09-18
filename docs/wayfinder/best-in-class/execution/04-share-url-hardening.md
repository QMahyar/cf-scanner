# 04: Share-URL hardening (missing-? recovery + credential shape check)

**What to build:** pasting a slightly malformed proxy share link gives an actionable error (or a recovered parse) at import time instead of dying deep in verification: links with query parameters but no `?` separator are recovered, and truncated/undecodable credentials are rejected with a clear message before any subprocess spawns.

**Blocked by:** None (can start immediately).

**Status:** done

Spec: `../spec-best-in-class.md` §P0-4. Inherits spec §6 execution rules.

- [x] Missing-`?` recovery at SIP002 parse head (single pass, bounded); well-formed-link behavior unchanged
- [x] Shape-only credential check (segment count / base64url decodability) surfaces an actionable error pre-spawn via the existing ignored+errors / skip-warn paths; no signature validation, no new dependency
- [x] No auto-join of `&`-in-path, no hostname typo rewriting (explicitly rejected, spec §R10)
- [x] Parser unit tests for each new case; `cargo test` + clippy `-D warnings` + fmt green

## Result

Done 2026-09-18. Touched only `src/configs/` (code + tests).

- (a) `recover_missing_question_mark` at the `parse_sip002` head
  (`src/configs/uri.rs`): one normalization attempt over a bounded (+1
  byte) buffer when no `?` precedes any `#`. A `/`-led `key=value` run
  reattaches whole (`.../security=tls&sni=x` → `.../?security=tls&sni=x`);
  otherwise the first `&` past the userinfo (last-`@` split, so raw `&` in
  passwords is preserved) becomes `?` (`:443&security=tls` →
  `:443?security=tls`). Port-glued keys (`:443security=tls`) stay a loud
  `bad URL` error rather than a misparse. Entries already carrying `?`
  return borrowed/byte-identical, which also implements the row-8b
  rejection (a real query is never merged with `&` path segments); no
  hostname rewriting anywhere (row 8c stays dropped).
- (b) `check_jwt_credential_shape` in `finish_spec`
  (`src/configs/mod.rs`): inspects only `eyJ`-prefixed dotted ids (every
  JWT header is base64url `{"`, truncation cuts the tail), so UUIDs,
  `not-a-uuid`, and ordinary dotted passwords pass through untouched.
  Arity must be 3 with every segment base64-decodable (via existing
  `base64_any`, no new dep, no signature checks); otherwise an actionable
  `... re-paste the full credential` error that carries no credential
  bytes. It rides the existing `parse_subscription` ignored+errors and
  phase-2 skip-warn paths with no new plumbing; covers vless/trojan
  userinfo, the `id`/`password` query fallback, vmess `id`, and xray-JSON
  ids via the shared choke point.
- Tests (9 new in `src/configs/mod.rs`, none deleted): `&`-form and
  `/`-equals-form recovery incl. fragment preservation, userinfo-`&`
  preservation, ambiguous-input rejection, `?`-present no-op (8b pin),
  well-formed bypass table, JWT reject table (2-seg / 4-seg / empty-seg /
  undecodable-seg + id-fallback + vmess paths), non-JWT accept table
  (UUID, `not-a-uuid`, `my.secret`, hostile passwords, full valid JWT),
  subscription ignored+errors surfacing.
- Gates: `cargo test` green all targets (lib 675 passed / 0 failed;
  bin 57; integration 16+2; property 16 incl. URI round-trip/never-panic
  props; xray-lifecycle 2), `cargo clippy --all-targets -- -D warnings`
  green, `cargo fmt` + `cargo fmt --check` green. Note: `rust-engineering`
  skill unavailable (load failed), proceeded per spec §6 + AGENTS.md;
  mid-work tree redness from parallel tickets (socks E0225, socks test,
  probe.rs fmt, TORN_* dead code) was left untouched per scope and is
  green at completion.
