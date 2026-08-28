# CF-Scanner Quality Hardening — Progress Tracker

> **Status:** BATCHES A+B+C COMPLETE → D1 (version bump) pending user decision
> **Map:** [#10 Wayfinder: CF-Scanner Quality Hardening — v0.12.0](https://github.com/QMahyar/cf-scanner/issues/10)
> **Last updated:** 2026-08-28

## How to resume this work

1. Read this file to understand current state
2. Check the map issue (#10) for the full picture and decisions made
3. D1 is the only remaining ticket — propose a version number to the user

## Ticket Status

| Batch | Ticket | Issue | Status | Verified | Tests | Merged |
|-------|--------|-------|--------|----------|-------|--------|
| A | A1: Security Fixes | [#11](https://github.com/QMahyar/cf-scanner/issues/11) | done | sweep | 393 pass | merged |
| A | A2: Ponytail Cleanups | [#13](https://github.com/QMahyar/cf-scanner/issues/13) | done | sweep | 393 pass | merged |
| A | A3: UI Fixes | [#12](https://github.com/QMahyar/cf-scanner/issues/12) | done | sweep | svelte-check 0 err | merged |
| B | B1: Performance | [#14](https://github.com/QMahyar/cf-scanner/issues/14) | done | sweep | 393 pass | merged |
| B | B2: PlanHosts Enum | [#15](https://github.com/QMahyar/cf-scanner/issues/15) | done | sweep | 393 pass | merged |
| C | C1: Enums | [#16](https://github.com/QMahyar/cf-scanner/issues/16) | done | sweep | 393 pass | merged |
| C | C2: Newtypes | [#17](https://github.com/QMahyar/cf-scanner/issues/17) | done | sweep | 393 pass | merged |
| C | C3: Fixes | [#18](https://github.com/QMahyar/cf-scanner/issues/18) | done | sweep | 393 pass | merged |
| C | C4: Status | [#19](https://github.com/QMahyar/cf-scanner/issues/19) | done | sweep | 393 pass | merged |
| C | C5: parse_cidr | [#20](https://github.com/QMahyar/cf-scanner/issues/20) | done | sweep | 393 pass | merged |
| D | D1: Version Bump | [#21](https://github.com/QMahyar/cf-scanner/issues/21) | ready | — | — | — |

## What shipped on main

### Batch A — Security + Trivial Cleanups + UI (merged first)
- RealFetch body-size cap (64 MiB)
- warp.rs server_public_key() graceful fallback instead of panic
- CSP: removed unsafe-inline from style-src
- Probe URLs: https:// only
- SSRF: documented RFC1918 relaxation
- De-duped unix_now(), replaced time_seed() with OsRng
- Inlined validate_cidr(), validate_endpoint(), ws_network(), ipv4()
- Removed write_pool() wrapper, unused _rng parameter
- Made fragment_block() private
- Farsi string fixed in English locale
- color-scheme: dark, tabular-nums, latency right-align
- Skip-to-content link, table caption, sticky IP column
- Indeterminate progress bar, dismissible banner, scroll-padding-top

### Batch B — Performance + Refactors (merged second)
- xray_fetch: spawn_blocking prevents runtime panic
- for_each_result: snapshot under lock, iterate outside
- ports: Arc<Vec<u16>> for cheap cloning
- Verdict: box-once, clone for batch
- plan_hosts_iter: concrete PlanHosts enum replaces Box<dyn Iterator>

### Batch C — API Contract Breaks (merged third)
- FragmentPreset enum (was String)
- Verifier enum (was Option<String>)
- Port newtype (rejects 0 at deserialization)
- ScanEvent::FailedPayload struct (was bare String)
- invalid_config now returns 422 (was 400)
- RegisterRequest.overwrite: bool with #[serde(default)] (was Option<bool>)
- parse_cidr delegation documented

## Remaining

- D1: Version bump proposal — propose vX.Y.Z, wait for user yes
  - Needs: Cargo.toml, npm/cf-scanner/package.json, npm/cf-scanner/install.js RELEASE_TAG
  - All three must match (CI enforces parity)
