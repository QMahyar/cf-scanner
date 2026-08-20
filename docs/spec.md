# Spec: CF-Scanner

Status: APPROVED (v0.4.0 baseline; deltas tracked in CHANGELOG/ADRs/review report)
Date: 2026-08-12
Source of truth: `docs/intent/cf-scanner.md` (confirmed user intent + verified
technical corrections)

## 1. Objective

A single cross-platform Rust binary that finds working Cloudflare IPs/endpoints
on ISP-restricted networks. Two modes:

- **CDN/proxy mode** — phase 1: TCP+TLS handshake scan of Cloudflare IPv4
  ranges; phase 2 (optional): verify candidate IPs against a real proxy config
  (VLESS/Trojan/VMess/SS via embedded Xray subprocess, with DPI-bypass
  fragmentation + SNI variants).
- **WARP mode** — UDP endpoint discovery over known Cloudflare WARP pools using
  a real WireGuard handshake probe; optional verification with the user's own
  WireGuard/AmneziaWG config; opt-in full config generation via Cloudflare's
  client registration API.

The binary serves a localhost-only HTTP API with an embedded browser frontend
("clean fast list": sortable IP:port / country / datacenter / latency / loss,
copy / save / reset). CLI flags, an interactive wizard, and the frontend all
drive the same in-process engine.

Users: normal users via browser UI; agents via CLI/JSON API.

Success: a user (or agent) can configure a scan (mode, phase, IP target count,
stop condition, configs) from CLI or browser, watch results arrive live, and
copy/save working IPs one-per-line — all in one binary, no external services.

## 2. Tech Stack (versions pinned to researched sources)

- Rust edition 2024; `tokio` (async runtime), `clap` 4 (CLI)
- `axum` (HTTP API), `tower-http` (static files), SSE via axum streams
- TLS probing: `tokio-rustls` + `rustls` (no OpenSSL)
- `serde` / `serde_json` (API + configs)
- Xray phase 2: spawn official `xray` binary subprocess, local socks
  inbound; fragment via freedom outbound + `sockopt.dialerProxy`
- WARP probe: `boringtun` (0.7.x) for WireGuard Init/parse; `reqwest` for the
  Cloudflare client API (`api.cloudflareclient.com/v0a884`) registration
- GeoIP: `maxminddb` 0.30 (built-in `geoip2` types), db-ip.com Lite MMDB
  embedded via `include_bytes!`
- Logging: `tracing` + `tracing-subscriber`; `anyhow` (errors)
- Frontend: one embedded HTML file, vanilla JS + native EventSource, custom
  design system (0.3.0) — see docs/review/product-review-2026-08-13.md
- Configuration: hand-rolled JSON in the platform data dir (`profiles.json`,
  `identity.json`, refreshed ranges); no config crate, no TOML

## 3. Commands

```
Build:            cargo build --release
Dev run:          cargo run -- serve            # start API + UI on 127.0.0.1:8765
Test:             cargo test
Lint:             cargo clippy --all-targets -- -D warnings
Fmt check:        cargo fmt --check
Scan (one-shot):  cargo run -- scan --mode cdn --preset quick --target 20
                  cargo run -- scan --mode warp --ports 2408,500
Refresh ranges:   cargo run -- ranges refresh
Install dist:     cargo install cargo-dist   (Arch: pacman -S cargo-dist)
Release dry-run:  dist plan --artifacts=all --tag=v0.4.0
Release:          dist build --artifacts=all --tag=v0.4.0 && dist host ... (CI)
```

## 4. Project Structure

```
src/
  main.rs            CLI entry (clap): serve | scan | ranges | wizard |
                     warp-config
  server.rs          axum app: API routes, SSE, static frontend
  engine/            ScanController: orchestration, stop conditions, progress
    mod.rs           controller, event stream re-sync, pool planning/sampling
    cdn.rs           CDN phase-1 probe loop + phase-2 handoff
    phase2.rs        phase-2 real-config verification orchestration
    warp.rs          WARP UDP probe orchestration
  ranges.rs          bundled CF ranges, refresh, custom CIDR, exclusions
  xray.rs            xray binary management: download/cache/checksum, spawn,
                     config build (fragment/sockopt), per-IP verdict
  configs.rs         parse vless:// trojan:// vmess:// ss:// URIs, sub URLs,
                     Xray JSON → normalized outbound spec
  warp.rs            WARP pools, UDP probe (boringtun), loss/latency
  warpgen.rs         registration API client (v0a884), wgconf builder,
                     WARP+ license binding
  verify.rs          phase-2 tunnel + wgconf verification
  wgconf.rs          WireGuard/AmneziaWG config parse + render
  paths.rs           platform data-dir paths
  probe.rs           TLS handshake probe + scoring (latency)
  geo.rs             mmdb lookup (country), /cdn-cgi/trace colo parse
  cli_wizard.rs      interactive prompts over the same API
  api/               request/response types (the contract all UIs share)
embed/
  index.html         single-file frontend (vanilla JS + native EventSource)
data/
  cf-ranges.txt      official IPv4 CIDRs
  cf-ranges-v6.txt   official IPv6 CIDRs (opt-in since v0.2.0)
  warp-pools.txt     known WARP endpoint pools
  xray-version.txt   pinned xray release tag
  bundled/           release-bundled binaries (tracked 0-byte placeholders)
build.rs             xray download + .dgst verify for release bundles; geoip
                     mmdb (db-ip.com Lite Country-only, CC BY 4.0) download →
                     OUT_DIR embed
tests/               integration tests (engine + API)
docs/                intent, spec, ADRs, review, README
tasks/               plan.md, todo.md
Cargo.toml           app manifest
dist-workspace.toml  dist (cargo-dist) workspace config
wix/                 MSI installer source
.github/workflows/   checks.yml (PR gates), release.yml (generated by dist)
```

## 5. Code Style

- Idiomatic 2024 Rust: `Result<T, anyhow::Error>` at boundaries, typed errors
  internally; `async` only where I/O is real.
- Public API types in `src/api/`; engine returns domain types; server maps
  domain → API (no serialization in engine).
- Every public async function that touches the network takes a timeout;
  no unbounded loops — all scan loops check stop conditions every iteration.
- Naming: snake_case; verbs for tasks (`probe`, `verify`), nouns for types
  (`Verdict`, `ScanConfig`).
- No comments unless explaining WHY (doubt-driven style); no dead code;
  clippy runs with `--all-targets -- -D warnings` in CI (enforced by the
  CI invocation, not by a crate-level attribute).

Example (style reference):

```rust
pub struct ScanConfig {
    pub mode: Mode,                 // Cdn | Warp
    pub target: Target,             // count or preset
    pub stop: StopCondition,        // after N found | N + cap | run-until
    pub ports: Vec<u16>,            // default [443]
    pub exclude: Vec<IpNet>,        // dirty ranges
}

pub struct Verdict {
    pub ip: Ipv4Addr,
    pub port: u16,
    pub latency_ms: Option<u16>,
    pub loss_pct: Option<f32>,      // WARP + phase 2 only
    pub phase2: Option<Phase2Verdict>,
}
```

## 6. Testing Strategy

- Framework: built-in `#[test]` + `tokio::test`; integration tests hit the
  engine and the axum API directly (no network — mock/inject transports).
- Unit: CIDR expansion, exclusion matching, URI parsers (vless/trojan/vmess/
  ss/subscription), wgconf parser, fragment preset → Xray config JSON builder,
  mmdb lookup, stop-condition state machine.
- Integration: simulated candidate stream (stubbed probe results) driving
  ScanController; API contract tests (start scan, SSE stream, results, reset).
- WARP probe: golden-packet tests — hand-crafted 148B Init / 92B Response /
  64B Cookie vectors; boringtun round-trip test with a local test keypair
  (parse our own Init in a peer Tunn).
- Live smoke tests (real xray phase 2, WARP handshake, ranges refresh) are
  gated behind `#[ignore]` and run manually with `CFSCANNER_SUB_URL` set (a
  live subscription URL); never run by default in CI.
- Coverage bar: whole-project lines >= 70% enforced in CI
  (`cargo llvm-cov --all-targets --fail-under-lines 70`); core engine modules
  targeted at >= 85% and spot-checked during review (not CI-enforced), UI
  served smoke test (frontend loads, SSE connects).
- All network tests use injected mock transports; never hit real
  Cloudflare/WARP endpoints in tests.

## 7. Boundaries

- **Always:** run `cargo test` + `cargo clippy -D warnings` + `cargo fmt
  --check` before committing; validate every user input (ports 1-65535, valid
  CIDRs, URI schemes); check `.dgst` checksums for downloaded xray binaries;
  bind 127.0.0.1 only unless an explicit flag changes it; keep challenge
  content (configs, generated keys) out of logs.
- **Ask first:** adding dependencies; changing the API contract
  (`src/api/`); modifying dist/release config; bundling a new binary or data
  file; changing the default scan behavior.
- **Never:** log or transmit imported configs/keys; embed secrets; remove a
  test to make CI green; commit xray binaries or mmdb into git (large +
  rebuilt); scan unrelated networks (ranges come only from official CF lists,
  WARP pools, or explicit user input).

## 8. Success Criteria

- [ ] `cargo run` starts the server on 127.0.0.1, prints URL, offers browser
- [ ] CDN phase-1 scan runs with presets + custom count, ports, exclusions,
      stop-after-N + cap; results live in frontend and API
- [ ] Phase 2 verifies a candidate IP through embedded Xray with the user's
      config; verdict includes fragment preset + SNI; xray binary bundled in
      release archives (fallback: checksum-verified runtime download)
- [ ] WARP mode probes known pools × ports with WG Init; working = open +
      zero probe loss (latency + 0% loss); works with user wgconf (incl.
      AmneziaWG-style)
- [ ] Opt-in WARP registration produces a valid wgconf via v0a884 API,
      exported as text/.conf; WARP+ binding option present
- [ ] Results: last-scan-only + reset; sort by latency/country/datacenter/loss;
      copy with ports / raw IPs (one per line, no trailing whitespace); save
- [ ] GeoIP: country via embedded mmdb offline; datacenter colo via
      /cdn-cgi/trace in phase 2
- [ ] `dist plan` passes for the 3-target matrix (linux x86_64/aarch64 +
      windows x86_64); PR CI runs test+clippy+fmt
- [ ] README documents Termux musl caveat + xray glibc note + SmartScreen note

## 9. Decisions (confirmed 2026-08-12)

1. Server default port **8765**, `--port` flag.
2. **Xray delivery: bundled in releases.** The dist build downloads the pinned
   xray binary + `.dgst` and bundles it in every release archive (dist
   ExtraArtifact). Runtime graceful fallback: if the binary is absent, offer a
   checksum-verified download into the data dir (covers dev builds and manual
   setups).
3. CLI output for agents: newline-delimited JSON on stdout for one-shot
   `scan`; wizard stays interactive.
4. Data dir via the `directories` crate (OS-appropriate paths).
5. UI language: English for v1.

### ADR trail

Each decision is recorded in `docs/decisions/`; shipped reality vs this spec
is reconciled in the
[finished-product review (2026-08-13)](review/product-review-2026-08-13.md)
and `CHANGELOG.md`.

- [ADR-001 — xray subprocess and bundling](decisions/ADR-001-xray-subprocess-and-bundling.md)
- [ADR-002 — boringtun WARP probes](decisions/ADR-002-boringtun-warp-probes.md)
- [ADR-003 — db-ip embedded GeoIP](decisions/ADR-003-dbip-embedded-geoip.md)
- [ADR-004 — DPI fragment chain](decisions/ADR-004-dpi-fragment-chain.md)
- [ADR-005 — single binary, contract first](decisions/ADR-005-single-binary-contract-first.md)
- [ADR-006 — no history, no telemetry](decisions/ADR-006-no-history-no-telemetry.md)
- [ADR-007 — central versioning and publishing](decisions/ADR-007-central-versioning-and-publishing.md)