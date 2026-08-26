# Plan 015: Close the IPv4-mapped-IPv6 guard bypass and pin the Origin check to the served port

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md`.
>
> **Drift check (run first)**: `git diff --stat 51c4711..HEAD -- src/server/mod.rs src/server/guard.rs src/ranges.rs`
> On mismatch with the excerpts below, STOP.

## Status

- **Priority**: P1
- **Effort**: S–M
- **Risk**: LOW–MED (origin pinning could break a legitimate caller — tests + manual check cover the UI, tray, and curl paths)
- **Depends on**: none
- **Category**: security
- **Planned at**: commit `51c4711`, 2026-08-26

## Why this matters

Two localhost-boundary defects, both verified in code:

1. **IPv4-mapped IPv6 literals bypass BOTH safety guards.** `::ffff:127.0.0.1`
   fails `is_loopback()` as a V6 address:
   - `banned_ip` (`src/server/mod.rs:276-287`) never normalizes via
     `to_ipv4_mapped()`, so a custom_cidr written in mapped form passes the
     API admission gate that exists to stop scans of loopback/RFC1918/link-
     local space (`server/mod.rs:231-244` documents that gate).
   - `validate_fetch_url` (`src/ranges.rs:629-631`) checks the raw V6 for
     loopback/unspecified/fe80::/10 — a bracketed mapped-v6 literal passes
     while connecting as its embedded v4 address. The guard's own invariant
     ("literal loopback/link-local refused") should mean what it says,
     especially for user-supplied subscription URLs.
2. **The Origin check accepts any localhost port** (`src/server/guard.rs:18-38`):
   `host_allowed` strips the port and compares bare hosts, so a page served
   by ANY other local process on `http://127.0.0.1:<other-port>` passes the
   Origin check AND browsers classify it `Sec-Fetch-Site: same-site`
   (different port, same site for IP hosts — `guard.rs:59-63`). Such a page
   can drive scans, profiles, and WARP registration. First-party should mean
   "the CF-Scanner UI", not "anything on loopback".

## Current state

- `src/server/mod.rs:270-287` (verified):
  ```rust
  fn banned_ip(ip: &std::net::IpAddr) -> bool {
      if ip.is_loopback() || ip.is_unspecified() { return true; }
      match ip {
          std::net::IpAddr::V4(v4) => v4.is_private() || v4.is_link_local() || v4.octets()[0] == 0,
          std::net::IpAddr::V6(v6) => {
              v6.is_unicast_link_local() || matches!(v6.segments()[0], 0xfc00..=0xfdff)
          }
      }
  }
  ```
- `src/ranges.rs:614-639` (verified): `validate_fetch_url` — https-only, then
  the `unroutable` match over `url::Host::Ipv4/Ipv6/Domain`; V6 arm at
  629-631; test matrix at `ranges.rs:691-704` covers only canonical forms.
- `src/server/guard.rs:18-38` — `host_allowed` (strips after last `:`,
  compares against `["127.0.0.1", "localhost"]`) and `origin_allowed`
  (parses the Origin header, calls host_allowed). `guard.rs:59-63` —
  Sec-Fetch-Site same-site acceptance. Existing guard tests at
  `src/server/mod.rs:1540-1615`.
- The bound port: the server binds a `SocketAddr` derived in `src/main.rs`/
  `src/server/mod.rs` (`--port` flag, default 8765). Find where the bound
  address is available relative to `router_with_dir` / the middleware state
  (`src/server/state.rs` holds `AppState`) — the port must reach the guard.
- Callers of the API: the embedded UI (same origin — sends the matching port
  or no Origin on same-origin GETs; browsers send Origin on POST), the tray
  (`src/tray.rs` uses the blocking client — check whether it sends Origin at
  all), and curl users (typically no Origin header). Pinning affects only
  requests that CARRY an Origin header.

## Commands you will need

| Purpose | Command | Expected |
|---|---|---|
| Server tests | `cargo test server` and `cargo test ranges` | all pass incl. new |
| Full gates | `cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check` | exit 0 |
| Manual | `cargo run -- serve` + UI + `curl -H "Origin: http://127.0.0.1:9999" -X POST .../api/scan` | UI works; cross-port Origin rejected 403 |

## Scope

**In scope**:
- `src/server/mod.rs` (`banned_ip` + tests)
- `src/server/guard.rs` (port pinning) and wherever the bound port is
  threaded into middleware state (`state.rs` / router construction)
- `src/ranges.rs` (V6 arm of `validate_fetch_url` + tests)

**Out of scope** (do NOT touch):
- DNS-resolve-then-connect hardening for hostname URLs (documented gap,
  L-effort, separate decision — see plans README "rejected/deferred")
- The Sec-Fetch-Site logic itself
- Any route handler or the API contract

## Git workflow

- Branch: `advisor/015-local-boundary`
- Commits: `fix(server): normalize ipv4-mapped ipv6 in the non-routable gate`, `fix(ranges): reject mapped-v6 loopback/link-local literals in the fetch guard`, `fix(server): pin origin checks to the served port`

## Steps

### Step 1: Normalize mapped-v6 in banned_ip

In `banned_ip`, in the V6 arm, FIRST check `if let Some(v4) = v6.to_ipv4_mapped()`
and recurse/apply the V4 checks (`is_private`, `is_link_local`, leading-0
octet); then the existing V6 checks. One WHY comment: mapped-v6 spellings of
v4 specials must not pass the v4 gate.

**Verify**: new tests in server/mod.rs test module (mirror the existing
`reject_non_routable` tests around :1540+): custom_cidr configs written as
`::ffff:192.168.1.0/120`-style mapped forms of private/loopback/link-local
targets are rejected with the same 400 as their v4 spellings. NOTE: mapped
CIDRs — check how `parse_cidr` handles a mapped-v6 prefix; if CIDR parsing
of mapped forms is itself unsupported, test the single-IP path through
whatever public seam exists (endpoint lists) and note it.

### Step 2: Normalize mapped-v6 in validate_fetch_url

In the V6 arm of `ranges.rs:629-631`:
```rust
url::Host::Ipv6(v6) => {
    if let Some(v4) = v6.to_ipv4_mapped() {
        let [a, b, _, _] = v4.octets();
        v4.is_loopback() || v4.is_unspecified() || (a == 169 && b == 254)
    } else {
        v6.is_loopback() || v6.is_unspecified() || v6.segments()[0] & 0xffc0 == 0xfe80
    }
}
```

**Verify**: extend the guard test table (`ranges.rs:691-704`) with
`https://[::ffff:127.0.0.1]/x` and `https://[::ffff:169.254.0.1]/x` → both
refused; `https://[2001:db8::1]/x` still allowed.

### Step 3: Pin Origin/Host to the served port

1. Thread the bound port into middleware state: read how `guard.rs`
   middleware is constructed (from_fn_with_state? Extension?) and where
   `router_with_dir` gets the bind address. Add the port (u16) to the state
   the guard already has (or a small new `GuardConfig { port: u16 }`).
2. `origin_allowed`: when the Origin header is present, require host match
   AND port match (`url.port_u16() == Some(bound_port)`). Keep accepting
   requests with NO Origin header (curl, same-origin GETs) exactly as today.
3. `host_allowed` for the Host HEADER: keep the current bare-host comparison
   (Host may legitimately omit port or carry it; do not over-tighten) —
   pin ONLY the Origin check. Add one WHY comment.

**Verify**: extend guard tests: Origin `http://127.0.0.1:<bound>` → allowed;
Origin `http://127.0.0.1:9999` → rejected (403 via the existing rejection
path — mirror how existing tests assert it); no Origin → allowed. Manual:
serve, use the UI (scan start/stop, profiles) — all works; curl POST with a
cross-port Origin → 403.

### Step 4: Tests summary

- mapped-v6: banned_ip unit tests + fetch-guard table rows (Steps 1–2).
- Origin pinning: guard tests incl. wrong-port rejection and no-Origin
  acceptance (Step 3).
- Full suite green; UI manual smoke.

## Done criteria

- [ ] `rg -n "to_ipv4_mapped" src/server/mod.rs src/ranges.rs` shows both guards normalizing
- [ ] New guard tests pass; existing guard/fetch tests pass unchanged
- [ ] UI fully functional against the pinned-origin server (manual)
- [ ] Full `cargo test` + clippy + fmt green; no out-of-scope files

## STOP conditions

- Pinning the Origin port breaks the tray (`src/tray.rs`) or any internal
  caller that sends an Origin header with a different/absent port — check
  tray.rs's client construction; if it sends Origin, update it IN SCOPE (it
  is an internal caller; note it) — if something EXTERNAL breaks, report.
- `parse_cidr`/endpoint validation cannot express the mapped-v6 test cases —
  test through the seam that CAN express them and report the gap (do not
  modify `src/api/` in this plan).
- The guard has no state channel for the port and threading one requires
  restructuring the middleware stack — report the structure; implement the
  smallest working variant (e.g. `Extension<GuardConfig>`) rather than a
  redesign.

## Maintenance notes

- Both guards now share the "normalize mapped-v6 first" rule — any future
  guard over IP literals (there is a third in plan 017's admission work)
  must follow it.
- The Origin port pin is the place future multi-port or unix-socket support
  would revisit.
- Reviewer scrutiny: confirm no legitimate browser flow sends a cross-port
  Origin to the API (same-origin fetches send the matching port; the UI is
  same-origin by construction).
