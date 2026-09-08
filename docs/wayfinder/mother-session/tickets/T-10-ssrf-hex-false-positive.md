# T-10 — ssrf-hex-false-positive (F-10)

## Finding
`src/ranges/http.rs:53-69`: the domain-path SSRF check requires ALL chars in
`[0-9a-fA-FxX.]` + ≥1 digit — blocks legitimate domains that look hex-like
with a digit (`d0ad.beef`, `cafe0.bad`, `b00.cafe`).

## Verify
Read the check + its tests. Confirm a `d0ad.beef`-style host is rejected.

## Fix
Apply the hex-literal test ONLY when the host has IP-literal shape
(all-numeric/hex dotted quad, `0x`-prefixed, or decimal-integer literal);
ordinary hostnames with letters beyond `a-f` already pass — the gap is
hex-plausible names WITH digits. Tighten: reject iff host parses as an IPv4
literal alternative form (use `std::net::Ipv4Addr::from_str` failure + a
narrow hex-literal detector), keep the existing digit-present rule inside
that narrow scope.

## Test
- `d0ad.beef`, `cafe0.bad` subscription hosts → accepted.
- `0x7f.0.0.1`, `2130706433`, `0x7f000001` → still rejected.
- Existing SSRF tests green (loopback/link-local/unspecified still blocked).

## Files
`src/ranges/http.rs` (+ tests).

## Gates
`cargo test` + `cargo clippy --all-targets -- -D warnings` + `cargo fmt --check`.
