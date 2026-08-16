# Plan 004: Test hardening (review domain tests)

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving on. The
> repo's LSP diagnostics are UNRELIABLE (phantom errors) — **cargo is the
> only truth**. Report: branch, commit hash, verification output, and which
> items you changed. Drift → stop and report.

## Status

- **Priority**: P2 — **Effort**: M — **Risk**: LOW
- **Depends on**: none (but pairs with plan 001's `src/server.rs` — no file
  overlap)
- **Category**: tests, security
- **Planned at**: commit `cd4e3a5`, 2026-08-16

## Why this matters

The tests review found: fixtures committed with REAL credential-shaped
material (a live UUID + a WireGuard private key); a vacuous live-smoke test
that skips instead of asserting when gated; parsers with no fuzz/property
coverage; the xray spawn port-retry loop untested; and decode_chunked with
no bounds tests. All approved by the user, including adding `proptest` as a
dev-dependency.

## Current state (at base commit `cd4e3a5`)

1. **Fixtures carry real credentials**:
   - `tests/fixtures/vless-worker.txt` — a live-looking vless URI with UUID
     `6086b6d5-6874-4299-8ef9-33b01a2125aa`, server `104.17.160.217:2096`.
   - `tests/fixtures/warp-uri.txt` — `wg://`/`wireguard://` URIs with
     `private_key=39l0houfixtSIA4O3MQRDMX5fBNUQw72H+RivqX2EbI%3D`.
   - `tests/fixtures/warp-wgconf.txt` — same private key in `[Interface]`.
   These keep their parse-shape for tests but must not carry real secrets.
2. `tests/live_smoke.rs` — `vless_fixture_dials_its_own_server`:
   `#[ignore]`d, gated on `CFSCANNER_SUB_URL`; when the env IS set and the
   dial fails, it SKIPS (eprintln + return) instead of asserting → the gate
   never fails CI. Same pattern may exist in `tests/cli_scan_agent.rs`
   (check its live path).
3. `tests/property_tests.rs` — seeded-RNG property tests (no proptest dep)
   covering CIDR exclusion split + wgconf round-trip. No parser fuzz
   coverage for `parse_uri` (vless/trojan/ss/vmess), `parse_wg_entry`,
   `parse_cidr`, `decode_chunked`.
4. `src/ranges.rs:852` — `fn decode_chunked(mut input: &[u8]) -> Result<Vec<u8>>`:
   chunked-transfer decoder used by the /cdn-cgi/trace + probe GET paths. No
   bounds tests (huge length field, truncated stream, trailing garbage,
   malformed chunk size).
5. `src/verify.rs` — the xray spawn port-retry loop (3 attempts, fresh
   ephemeral port each time) is inline in `XrayTunnelProbe::probe`
   (lines ~96-123 of the base) — untested.
6. `src/configs.rs` — `sanitize_error_text`/`redact_line` landed in the base
   commit; check whether unit tests exist in its tests module; add a
   redaction table if missing (userinfo raw + %40, query/fragment cut,
   control chars, over-long truncation).

## User decision (binding)

- Add `proptest = "1"` as a dev-dependency (parser property tests).

## Commands you will need

| Purpose | Command                          | Expected on success |
|---------|----------------------------------|---------------------|
| Check   | `cargo check --tests`            | exit 0              |
| Tests   | `cargo test`                     | all pass            |
| Lint    | `cargo clippy --all-targets -- -D warnings` | exit 0    |
| Format  | `cargo fmt --check`              | exit 0              |

## Scope

**In scope**:
- `Cargo.toml` + `Cargo.lock` (proptest dev-dep only)
- `tests/fixtures/*.txt` (scrub secrets)
- `tests/live_smoke.rs`, `tests/cli_scan_agent.rs` (gate honesty)
- `tests/property_tests.rs` (extend)
- `src/verify.rs` (extract retry seam + tests; keep behavior identical)
- `src/ranges.rs` (decode_chunked tests only — add tests, DO NOT change the
  decoder unless a test proves a panic; then fix minimally)
- `src/configs.rs` (tests only)

**Out of scope**:
- `src/server.rs`, `src/main.rs`, `src/cli_wizard.rs` (plan 001)
- `src/api/types.rs`, `src/engine/*` (base-commit work; don't touch)
- `embed/index.html` (plan 002)
- Version bump (integrator)

## Git workflow

- Branch: `review/r6-tests` from `main` (`cd4e3a5`).
- Commit per item; message style `review: <what>`.
- Do NOT push or merge.

## Steps

### Step 1: proptest dev-dependency

Add to `[dev-dependencies]` in `Cargo.toml`:
```toml
proptest = "1"
```
Run `cargo check --tests` (updates `Cargo.lock`).

### Step 2: scrub fixture credentials (keep parse-shape)

- `tests/fixtures/vless-worker.txt`: UUID → `00000000-0000-0000-0000-000000000000`;
  keep server/port/sni/host/path/fp/packetEncoding (the dial tests still
  target the same host).
- `tests/fixtures/warp-uri.txt` + `warp-wgconf.txt`: private key →
  base64 of 32 zero bytes (`AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=`),
  public key → the WARP server constant is fine to keep (it's a public
  constant, `bmXOC+...`). Preserve all other fields.
- Check that no other committed file carries `39l0houfixt` or the UUID:
  `git grep -l "39l0houfixt\|6086b6d5"` must return nothing after the scrub.

**Verify**: `cargo test --test live_smoke -- --ignored` still runs the
parse tests (they skip the network paths on this machine; parse assertions
must pass).

### Step 3: live-smoke gate honesty

`tests/live_smoke.rs` `vless_fixture_dials_its_own_server` (and the same
pattern in `tests/cli_scan_agent.rs` if present): when `CFSCANNER_SUB_URL`
IS set, the dial outcome must be ASSERTED (refused/timeout → test failure),
not skipped; skip only when the env var is absent.

**Verify**: `cargo test --test live_smoke` (without the env var) passes and
prints skips; with a bogus `CFSCANNER_SUB_URL` set, `cargo test --test
live_smoke -- --ignored vless_fixture` FAILS on the dial assertion.

### Step 4: property tests for parsers (proptest)

Extend `tests/property_tests.rs`:
- `parse_uri`: for vless with tls+ws (+fp/sni/host/path/xudp), trojan,
  shadowsocks (aes-128-gcm), vmess: parse a valid sample → assert fields;
  proptest round-trip: render a known-good spec → parse → same fields
  (use the configs module's render/parse — check what `src/configs.rs`
  exposes for rendering; if no renderer exists, assert parse invariants:
  never panics on arbitrary strings, parsed port in 1..=65535, protocol
  preserved).
- `parse_wg_entry` (src/wgconf.rs): arbitrary non-empty strings never
  panic; valid wgconf text round-trips.
- `parse_cidr` (src/ranges.rs): arbitrary strings never panic; valid
  CIDRs parse and re-print canonically.
- `decode_chunked` (src/ranges.rs): valid chunked encodings of arbitrary
  byte payloads decode to the payload; truncated/bogus inputs return `Err`
  (never panic).

Pattern: follow the existing tests in `tests/property_tests.rs` (they use
`cf_scanner::ranges::SplitMix64` + manual loops; with proptest use the
`proptest!` macro with `".*"`/`vec(any::<u8>(), 0..256)` strategies).

**Verify**: `cargo test --test property_tests` all pass.

### Step 5: decode_chunked bounds tests

In `src/ranges.rs` tests module (find `mod tests`): add direct unit tests:
- empty input → Ok(empty) (match current behavior)
- one chunk of "hello" → b"hello"
- multi-chunk + trailing CRLF
- chunk-size field with a huge value (e.g. `ffffffff\r\n` — no body) →
  Err, no allocation blow-up
- truncated body → Err
- garbage chunk-size (non-hex) → Err
- trailer lines (`X-foo: bar\r\n`) before the final CRLF → Ok (match
  current behavior — READ the decoder first and assert its actual
  semantics).

**Verify**: `cargo test --lib ranges` all pass.

### Step 6: xray spawn port-retry seam + tests

`src/verify.rs`: extract the 3-attempt loop from `XrayTunnelProbe::probe`
into a free async fn (behavior-identical):
```rust
/// Retries a spawn that failed (usually a stolen ephemeral port), with a
/// fresh port per attempt; the last error wins after 3 tries.
async fn spawn_with_retry(
    mut attempt: impl FnMut(u16) -> Result<xray::XrayProcess>,
) -> Result<xray::XrayProcess>
```
Body: for attempt_no in 1..=3 { pick_ephemeral_port; match attempt(port) {
Ok → return; Err if <3 → debug log + continue; Err → return Err with
context "xray spawn failed after 3 attempts" } } — plus an unreachable
fallback that returns the last error (avoid `expect` in the refactor).
The probe calls `spawn_with_retry(|socks_port| { build_config(...)?;
xray::spawn(&trial_dir, &xray_bin, &cfg).await })` — keep the existing
debug-logging of ip/attempt.

Tests (in `src/verify.rs` tests module):
- fails twice then succeeds → Ok, exactly 3 closure calls, distinct ports
  (record them).
- fails all 3 → Err whose message contains "after 3 attempts".
The fake closure needs an `xray::XrayProcess` on success — construct one
without spawning? `XrayProcess` has private fields. Use a helper in the
tests module if `xray.rs` exposes one, else test the failure path only and
the "succeeds on attempt 1" path via a fake that returns
`Err` twice then... you cannot build XrayProcess without a child. **If
XrayProcess is not constructible in tests, restructure the seam to operate
on a result-typed value the tests can synthesize** (e.g. the retry function
is generic over the spawned value type `T`, tests use `Result<u16>`); this
is the approved approach — the seam must be testable.

**Verify**: `cargo test --lib verify` all pass.

### Step 7: redaction tests (src/configs.rs)

Check the tests module for existing `sanitize_error_text` coverage; add a
table test if missing:
- `user:pass@example.com/x` → `***@example.com/x`
- `user%40pass@...` → masked
- URL with query carrying ids: query stripped
- control characters stripped
- a >512-byte line truncated with `…`
- plain prose with `@` left alone

**Verify**: `cargo test --lib configs` all pass.

## Test plan

Covered by the steps: fixture scrub (Step 2), gate honesty (Step 3),
proptest suites (Step 4), decode bounds (Step 5), retry seam (Step 6),
redaction table (Step 7). Structural patterns: existing tests in
`tests/property_tests.rs`, `src/verify.rs` tests, `src/ranges.rs` tests.

## Done criteria

ALL must hold:
- [ ] `cargo test` exits 0 (all suites)
- [ ] `cargo clippy --all-targets -- -D warnings` + `cargo fmt --check` exit 0
- [ ] `git grep -l "39l0houfixt\|6086b6d5"` returns nothing
- [ ] `git grep -rn "proptest" Cargo.toml` shows the dev-dep
- [ ] Retry seam tests exist and pass; decode bounds tests exist and pass
- [ ] `git status` shows only the in-scope files modified
- [ ] Commit on `review/r6-tests`; report hash + verification output

## STOP conditions

- A cited location doesn't match (drift).
- `decode_chunked` panics on a new test input (then fix the decoder
  minimally — it IS in scope for that bug only — and note it).
- `XrayProcess` can't be synthesized and restructuring the seam threatens
  behavior (stop and report your design instead of forcing it).
- proptest requires a Rust/edition feature the repo doesn't support (it's
  edition 2024; proptest 1.x is fine).

## Maintenance notes

- The fixture keys stay inert forever: never restore real configs into
  `tests/fixtures/`.
- `spawn_with_retry`'s context message is part of the API error surface
  (phase-2 failures) — keep it descriptive.