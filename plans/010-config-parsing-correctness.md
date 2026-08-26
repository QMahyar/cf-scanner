# Plan 010: Fix config-import parsing — VMess fields, base64 variants, numeric ports, default ports

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md`.
>
> **Drift check (run first)**: `git diff --stat 51c4711..HEAD -- src/xray.rs src/configs.rs`
> On mismatch with the excerpts below, STOP.

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: LOW (additive parsing acceptance + additive JSON fields; existing tests pin behavior)
- **Depends on**: none
- **Category**: bug
- **Planned at**: commit `51c4711`, 2026-08-26

## Why this matters

Four parsing bugs silently discard or corrupt valid user configs — the input
this whole product exists to consume:

1. **VMess configs are rebuilt without `alterId` and with the wrong cipher
   key**: `build_outbound` emits `{"id", "encryption": "none"}` for BOTH VLESS
   and VMess. `encryption` is the VLESS key; xray's VMess user cipher field is
   `security`. Parsed `alter_id`/`vmess_security` values are never read by any
   builder. Legacy-AEAD or cipher-pinned VMess candidates are falsely marked
   dead in phase 2.
2. **Two of the four common base64 variants are rejected** in `vmess://`/`ss://`
   payloads: unpadded standard-alphabet and padded URL-safe-alphabet both fail
   the current STANDARD→URL_SAFE_NO_PAD chain — a very common generator
   output for vmess links.
3. **Numeric `port` in VMess JSON is rejected** (`{"port":443}` → "missing/
   invalid port"); only string ports work.
4. **SIP002 URIs without an explicit port are rejected** with "missing port",
   though 443 is the universal default for vless/trojan share links.

## Current state

- `src/xray.rs:90-98` (verified):
  ```rust
  let mut outbound = match spec.protocol {
      Protocol::Vless | Protocol::Vmess => json!({
          "tag": "proxy",
          "protocol": spec.protocol.as_str(),
          "settings": {"vnext": [{
              "address": dial_ip.to_string(), "port": spec.port,
              "users": [{"id": spec.user_id, "encryption": "none"}],
          }]},
      }),
  ```
- `src/configs.rs` — `OutboundSpec` fields `alter_id` and `vmess_security`
  (~142-146) are populated by `parse_vmess` (~426-427) and `parse_xray_json`
  (~540-551) but never read anywhere (grep to confirm before editing).
- `src/configs.rs:629-635` — `base64_any` helper tries
  `base64::engine::STANDARD` then `URL_SAFE_NO_PAD` (read exact code).
  base64 crate version is 0.23.x (engine API: `general_purpose::STANDARD`,
  `STANDARD_NO_PAD`, `URL_SAFE`, `URL_SAFE_NO_PAD` — verify against the
  vendored crate docs in `~/.cargo` or docs.rs for the locked version).
- `src/configs.rs:413-420` — the VMess JSON `get` helper reads only
  `v.as_str()` (read exact code); `port` and `aid` both affected.
- `src/configs.rs:349` — `parse_sip002`: `url.port().ok_or_else(|| anyhow!("missing port"))?`
  for vless/trojan (read the function; keep the `ss://` path as-is).
- Existing tests to mirror: `configs.rs` `#[cfg(test)]` module has
  `vmess_accepts_url_safe_base64` and URI parse tests; `tests/property_tests.rs`
  has `render_uri` round-trip property tests. Table-driven style.

Conventions (from `AGENTS.md`/`CONTEXT.md`): typed errors internally,
`anyhow` at boundaries is fine here (configs.rs already uses `anyhow!`);
engine consumes `api::types` (ADR-011) — no changes to `src/api/` needed for
this plan; no comments unless WHY; clippy `-D warnings` gate.

## Commands you will need

| Purpose | Command | Expected |
|---|---|---|
| Unit tests | `cargo test configs` | all pass incl. new |
| Full gates | `cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check` | exit 0 |

## Scope

**In scope**:
- `src/xray.rs` (build_outbound VMess arm only)
- `src/configs.rs` (base64_any, VMess get helper, parse_sip002 port default)
- Test modules in both files and/or `tests/property_tests.rs`

**Out of scope** (do NOT touch):
- `src/api/**` (contract untouched — `OutboundSpec` already carries the fields)
- `src/inline_verify.rs` (inline verifier only handles plain VLESS/Trojan by
  design; VMess always goes through xray — see ADR-001)
- Trojan/SS builders in xray.rs
- Any subscription-fetch logic (plan 016's territory)

## Git workflow

- Branch: `advisor/010-config-parsing`
- Commits: `fix(xray): emit vmess alterId and security in build_outbound`, `fix(configs): accept all four base64 variants in vmess/ss payloads`, `fix(configs): numeric port/aid in vmess json`, `fix(configs): default vless/trojan sip002 port to 443`

## Steps

### Step 1: VMess build_outbound fields

1. Split the match arm:
   ```rust
   Protocol::Vless => json!({ ... unchanged, "encryption": "none" ... }),
   Protocol::Vmess => json!({
       "tag": "proxy",
       "protocol": spec.protocol.as_str(),
       "settings": {"vnext": [{
           "address": dial_ip.to_string(), "port": spec.port,
           "users": [{
               "id": spec.user_id,
               "alterId": spec.alter_id,          // u32; emit always (xray accepts 0)
               "security": spec.vmess_security.as_deref().unwrap_or("auto"),
           }],
       }]},
   }),
   ```
   Read `OutboundSpec` for exact field types first; if `alter_id` is
   `Option<u32>` emit `alterId: spec.alter_id.unwrap_or(0)`.
2. Keep `encryption` OUT of the VMess users object (xray treats it as unknown
   there at best).

**Verify**: `cargo test xray` green; new test (Step 5) passes.

### Step 2: Accept all four base64 variants

In `configs.rs` `base64_any`: extend the chain to
`STANDARD` → `STANDARD_NO_PAD` → `URL_SAFE` → `URL_SAFE_NO_PAD`
(using `base64::engine::general_purpose::{...}` per the locked crate version —
read the current imports). Keep the existing function signature and error
behavior (returns `Option<Vec<u8>>` or Result — match current).

**Verify**: `cargo test configs` green; new table test covers all four
encodings of the same payload.

### Step 3: Numeric port/aid in VMess JSON

Change the `get` helper (or add `get_flex`) used by `parse_vmess` to accept
`value.as_str()` OR `value.as_u64()` (with `<= 65535` check for port; `aid`
as u64 too). Apply to `port` and `aid` reads.

**Verify**: `cargo test configs` green; new test parses
`{"v":"2","ps":"t","add":"h","port":443,"id":"...","aid":0,"scy":"auto", ...}`
(base64 of it) successfully.

### Step 4: Default vless/trojan port to 443

In `parse_sip002`, for the vless/trojan arms replace
`url.port().ok_or_else(|| anyhow!("missing port"))?` with
`url.port().unwrap_or(443)` (add one WHY comment: share links commonly omit
the default port). Leave `parse_ss` unchanged.

**Verify**: `cargo test configs` green; new test parses
`vless://uuid@host` (no port) → port 443; `vless://uuid@host:8443` → 8443
(existing tests must still pass).

### Step 5: Tests

In `src/configs.rs` tests module + `src/xray.rs` tests module (mirror the
existing table style):

1. `vmess_build_emits_alterid_and_security` — build an `OutboundSpec`
   (Vmess, alter_id Some(64), security Some("aes-128-gcm")), call the
   builder `build_outbound` (or whatever the function is named — read
   xray.rs), assert the JSON contains `"alterId": 64` and
   `"security": "aes-128-gcm"`, and VLESS output still has
   `"encryption": "none"` (second assertion in a separate test).
2. `base64_accepts_all_variants` — one payload, four encodings, all parse to
   the same VMess spec.
3. `vmess_accepts_numeric_port_and_aid`.
4. `sip002_defaults_port_to_443`.

**Verify**: `cargo test` full suite green.

## Done criteria

- [ ] `rg -n "alter_id|vmess_security" src/xray.rs` shows both fields read in the VMess arm
- [ ] `rg -n "STANDARD_NO_PAD" src/configs.rs` present
- [ ] All four new tests exist and pass; full `cargo test` green
- [ ] `cargo clippy --all-targets -- -D warnings` and `cargo fmt --check` exit 0
- [ ] No files outside scope modified

## STOP conditions

- The locked base64 version's engine constants differ from the four named
  here — read the vendored crate source (`cargo doc --open` or
  `~/.cargo/registry/src/.../base64-0.23.x/`) and use its real constants;
  report if a variant genuinely cannot be expressed.
- `OutboundSpec` lacks a field the builder needs (e.g. alter_id not stored) —
  report; do NOT add fields to `OutboundSpec` if that changes `src/api/`
  (it shouldn't — verify where OutboundSpec lives first; if it IS in
  `src/api/types.rs`, adding a field needs maintainer sign-off per AGENTS
  "ask first" — STOP and report).
- Existing tests fail after Step 1 because they pinned the WRONG vmess output
  (missing fields) — update those assertions and call it out in the report.

## Maintenance notes

- The VMess builder now mirrors xray's user schema; if xray support for
  `encryption` in vmess users changes upstream, revisit.
- The four-engine base64 chain is the canonical decoder for ANY future
  token-ish field — reuse `base64_any`, don't inline engine chains.
- Reviewer scrutiny: confirm no config that previously parsed now FAILS
  (changes are additive only); the full existing test suite is the guard.
