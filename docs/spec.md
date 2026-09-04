# Spec: CF-Scanner

> **SUPERSEDED 2026-09-02:** the product is now a pure CLI — the HTTP
> server, browser UI, and tray described below were removed (ADR-012).
> Commands and architecture live in `README.md` and `AGENTS.md`. The
> engine/scan-model sections remain accurate; every `serve`/`ui/`/tray
> reference is historical.

Status: APPROVED (v0.4.0 baseline; deltas tracked in CHANGELOG/ADRs/review report)
Date: 2026-08-12
Source of truth: `docs/intent/cf-scanner.md` (confirmed user intent + verified
technical corrections)

## 1. Objective

A single cross-platform Rust binary that finds working Cloudflare IPs/endpoints
on ISP-restricted networks. Two modes:

- **CDN/proxy mode** — phase 1: TCP+TLS handshake scan of Cloudflare IPv4
  ranges, with selectable probe protocol (`--probe tcp|tls|http`; HTTP mode
  GETs `/cdn-cgi/trace` and captures the colo during phase 1). Every verdict
  carries reliability signals (`sent`/`received`/`loss_pct`, `fail_reason`)
  and failures are stored, never silently dropped. Opt-in scan-time filters:
  `--loss-threshold`, `--min-latency`, `--idle-hold-ms` (post-handshake RST
  detection), `--colo` (kept codes), `--neighbor-scan` (same-/24 widening
  after a hit). Phase 2 (optional): hybrid verification of candidate IPs
  against a real proxy config — plain VLESS/Trojan (no fragmentation, no
  `ws`) verifies in-process (`inline_verify.rs`, no subprocess); every other
  combo (VMess/SS, `ws`/`grpc`/`xhttp` transports, any DPI fragmentation
  preset) verifies through the embedded Xray subprocess, with DPI-bypass
  fragmentation + SNI variants. Each `Phase2Verdict.verifier` reports
  `inline` vs `xray` so the UI can surface the path. Opt-in `--speed-test`
  pulls a capped 8 MiB sample through each passing endpoint and records
  `speed_test_mbps` (`--min-speed` gates the working set).
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
- `axum` (HTTP API), `rust-embed` (embedded UI assets), SSE via axum streams
- TLS probing: `tokio-rustls` + `rustls` (no OpenSSL)
- `serde` / `serde_json` (API + configs)
- Xray phase 2: spawn official `xray` binary subprocess, local socks
  inbound; fragment via freedom outbound + `sockopt.dialerProxy`. Hybrid
  verifier: `verify::HybridTunnelProbe` routes `FragmentPreset::Off` +
  `vless|trojan` + non-`ws` + `tls|none` to `inline_verify::InlineTunnelProbe`
  (in-process, ~0ms spawn), everything else to `xray::XrayTunnelProbe`.
- WARP probe: `boringtun` (0.7.x) for WireGuard Init/parse; `reqwest` for the
  Cloudflare client API (`api.cloudflareclient.com/v0a884`) registration
- GeoIP: `maxminddb` 0.30 (built-in `geoip2` types), db-ip.com Lite MMDB
  embedded via `include_bytes!`
- Logging: `tracing` + `tracing-subscriber`; `anyhow` (errors)
- Frontend: Svelte 5 (runes-only) + Tailwind 4 + Vite 7 in `ui/` compiled to
  committed `ui/dist`, embedded via `rust-embed` (`src/server/mod.rs`),
  bilingual EN/FA, single origin, no external assets. See
  `docs/review/product-review-2026-08-13.md`. Dev: `cd ui && npm ci && npm run check && npm run build`; commit `ui/src` with `ui/dist`.
- Tray (Windows-only): `tray-icon` 0.24 (default-features off) + `winreg` 0.56
  behind `serve --tray`; `--autostart` registers `serve --tray` at
  `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\CF-Scanner` (requires
  `--tray`; `remove` works without). Non-Windows stub logs and serves without
  tray.
- Caps (enforced in `src/api/limits.rs` + `src/api/validate.rs`): ports 1-65535,
  max 64 distinct; concurrency 1-1000 (default 64); timeout 100-30000 ms
  (default 3000); scan count ≤100_000; `stop.found`/`cap` ≤100_000_000;
  warp endpoints ≤2048, `probes_per_endpoint` 1-10; phase2 entries ≤8, each
  ≤8 KiB, SNIs ≤256 B, probe URLs ≤2 KiB, `wgconf` ≤64 KiB (2 MiB body cap).
  Competitive catch-up caps (§10): loss threshold 0-100; min latency
  1-30000 ms; idle hold 0-60000 ms; colo codes ≤16 (3-5 ASCII letters each);
  HTTP status codes 100-599 (default 200,301,302); neighbor breadth 0-64;
  speed sample 8 MiB per endpoint, 30 s timeout.
- Configuration: hand-rolled JSON in the platform data dir (`identity.json`
  for WARP keys with 0600 on Unix, `refreshed-ranges.json` +
  `refreshed-ranges-v6.json`);
  no config crate, no TOML. CLI `--phase2-configs` accepts local file paths;
  the HTTP API accepts URLs/URIs only (file paths are CLI-only, validated at
  `server/mod.rs::start_scan`).

## 3. Commands

```
Build:            cargo build --release
Dev run:          cargo run -- serve --open     # start API + UI on 127.0.0.1:8765
Test:             cargo test
Lint:             cargo clippy --all-targets -- -D warnings
Fmt check:        cargo fmt --check
Scan (one-shot):  cargo run -- scan --preset quick --target 20 --cap 5000
                  cargo run -- scan --mode warp --count 512 --ports 2408,500
                  cargo run -- scan --phase2-configs vless://... --phase2-fragment medium
Serve (tray):     cargo run -- serve --tray --autostart   # Windows: tray + HKCU autostart
Wizard:           cargo run -- wizard
Ranges:           cargo run -- ranges refresh [--ipv6]
Warp gen:         cargo run -- warp-config generate [--out wg.conf] [--license KEY]
Warp export:      cargo run -- warp-config export [--out wg.conf]
Export link:      cargo run -- export-config --config vless://... --ip 1.2.3.4 --port 443
Install dist:     cargo install cargo-dist   (Arch: pacman -S cargo-dist)
Release dry-run:  dist plan --tag=vX.Y.Z
Release:          dist build --output-format=json "--artifacts=global" ... (CI only, on tag push)
```

## 4. Project Structure

```
src/
  main.rs            CLI entry (clap): serve | scan | ranges | wizard |
                     warp-config | export-config
  server/{mod,state,error,guard,sse}.rs  axum app: API routes, SSE, static frontend via rust-embed
  engine/            ScanController: orchestration, stop conditions, progress
    mod.rs           controller, event stream re-sync, pool planning/sampling
    cdn.rs           CDN phase-1 probe loop + phase-2 handoff
    phase2.rs        phase-2 real-config verification orchestration (hybrid routing)
    warp.rs          WARP UDP probe orchestration
    plan.rs          plan + SplitMix64 sampling (dense /24 skip, lazy Every)
  ranges/{mod,pool,official,http}.rs  bundled CF ranges, pool, refresh, custom CIDR, exclusions
  xray.rs            xray binary management: download/cache/checksum, spawn,
                     config build (fragment/sockopt), per-IP verdict
  verify.rs          HybridTunnelProbe (inline vs xray) + per-attempt trial dirs, socks probe
  inline_verify.rs   in-process vless/trojan verifier (no xray spawn)
  socks.rs           SOCKS5 GET through the tunnel
  tray.rs            Windows tray-icon + HKCU autostart (stub elsewhere)
  configs.rs         parse vless:// trojan:// vmess:// ss:// URIs, sub URLs,
                     Xray JSON → normalized outbound spec
  warp.rs            WARP pools, UDP probe (boringtun), loss/latency, SocketCache
  warpgen.rs         registration API client (v0a884), wgconf builder,
                     WARP+ license binding
  wgconf.rs          WireGuard/AmneziaWG config parse + render
  dgst.rs            strict .dgst SHA2-256 parser (shared with build.rs)
  paths.rs           platform data-dir paths (0600 secrets, write gate)
  probe.rs           probe transports (tcp connect, TLS handshake, HTTP trace)
                      + scoring (latency, loss, colo) via the injectable
                      `Transport` trait
  geo.rs             mmdb lookup (country), /cdn-cgi/trace colo parse
  cli_wizard.rs      interactive prompts over the same API (builds one engine
                      per scan so the chosen probe protocol runs)
  export.rs          result/bundle rendering (csv, json, base64, raw, singbox,
                      clash, sharelinks)
  engine/speed.rs    opt-in post-stop throughput test (capped sample per
                      phase-2-passing endpoint)
  api/{types,limits,validate,error}.rs  request/response contract + caps
ui/src               Svelte 5 (runes-only) + Tailwind 4 + Vite SPA
ui/dist              committed build output embedded via rust-embed
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
tasks/               wayfinder-map.md (effort tracker)
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
- Caps are single-sourced in `src/api/limits.rs`; `ScanConfig::validate()`
  enforces them before any scan starts. New request fields use
  `#[serde(default)]` so additive evolution stays compatible; `deny_unknown_fields`
  keeps unknown keys at 422 (`invalid_config`).
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
    pub probe_mode: ProbeMode,      // Tcp | Tls (default) | Http
    pub loss_threshold: Option<u32>,
    pub min_latency_ms: Option<u32>,
    pub idle_hold_ms: u64,          // 0 = off
    pub colo_filter: Vec<String>,   // empty = all regions
    pub neighbor_count: u32,        // 0 = off
    pub speed_test: bool,           // opt-in, needs phase2
    pub min_speed_mbps: Option<f32>,
}

pub struct Verdict {
    pub ip: Ipv4Addr,
    pub port: u16,
    pub latency_ms: Option<u32>,    // None = failed probe, see fail_reason
    pub loss_pct: Option<u32>,      // from sent/received probe counts
    pub fail_reason: Option<String>,// refused | timeout | tls_failed | http_status
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
  CIDRs, URI schemes, caps from §2) and reject over-cap requests (413 for
  profiles, 422 `invalid_config` for scan caps); check `.dgst` checksums for
  downloaded xray binaries; bind 127.0.0.1 only unless an explicit flag changes
  it; keep challenge content (configs, generated keys) out of logs; require
  `X-Requested-With: cf-scanner` on all state-changing API requests (CSRF
  hardening — the server guard rejects mutating methods without it).
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
      stop-after-N + cap; results live in frontend and API; caps enforced
      (ports ≤64, count ≤100k, stop ≤100M)
- [ ] Phase 2 hybrid verification: plain vless/trojan verifies in-process,
      everything else through embedded Xray with the user's config; verdict
      includes fragment preset + SNI + `verifier` (inline|xray); xray binary
      bundled in release archives (fallback: checksum-verified runtime download)
- [ ] WARP mode probes known pools × ports with WG Init; working = open +
      zero probe loss (latency + 0% loss); works with user wgconf (incl.
      AmneziaWG-style)
- [ ] Opt-in WARP registration produces a valid wgconf via v0a884 API,
      exported as text/.conf; WARP+ binding option present
- [ ] Results: last-scan-only + reset; sort by latency/country/datacenter/loss;
      copy with ports / raw IPs (one per line, no trailing whitespace); save
- [ ] GeoIP: country via embedded mmdb offline; datacenter colo via
  /cdn-cgi/trace in phase 2 (or phase 1 with `--probe http`)
- [ ] Frontend: Svelte 5 SPA in `ui/` → committed `ui/dist` via rust-embed,
      `npm run check && npm run build` before commit; `ui/dist` drift fails CI
- [ ] `dist plan` passes for the 3-target matrix (linux x86_64/aarch64 +
      windows x86_64); PR CI runs test+clippy+fmt+coverage+ui:a11y+version-parity
- [ ] README documents Termux musl caveat + xray glibc note + SmartScreen note
- [ ] Tray: `serve --tray` + `--autostart` (Windows) covered in README + QA runbook

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

## 10. Amendment (2026-09-04): competitive catch-up

Eleven CDN-mode gaps found in the 2026-09-03 competitor audit
(`docs/research/competitor-cf-scanners-2026-09-03.md`,
`docs/research/2026-09-03-competitor-cf-scanners.md`;
SenPaiScanner, XIU2 cfst, Morteza CFScanner, CrimsonCF, Waldon) shipped as
opt-in additions; default scan behavior is unchanged. Work tracked in
`docs/wayfinder/competitive-catchup/` (map + 11 tickets, all closed).

1. **Packet-loss rate** — `Verdict.sent/received/loss_pct`; `--loss-threshold`
   drops lossy results (above-threshold dropped, not stored).
2. **Colo filter** — `--colo HKG,NRT`; unknown-colo passes with a one-time
   warning; enforced where colo becomes known (phase 2, or phase 1 http).
3. **Phase-1 failure reasons** — `Verdict.fail_reason`; failures stored with
   `latency_ms: null`, sorted last, never counted as found.
4. **Richer CSV** — `...,phase2_latency_ms,speed_test_mbps,sent,received,
   loss_pct,fail_reason` (appended; old columns keep order).
5. **HTTPing probe mode** — `--probe tcp|tls|http`, `--http-status-code`;
   phase-1 colo capture.
6. **Share-link export** — `--export-format sharelinks`, batch form of
   `export-config`.
7. **Latency lower bound** — `--min-latency` drops below-bound verdicts.
8. **Idle-hold stability probe** — `--idle-hold-ms`; handshake-only latency;
   RST-after-idle fails the probe.
9. **gRPC/XHTTP verification** — parsed, verified through xray, exported to
   sing-box/clash. HTTPUpgrade stays parse-only (deferred).
10. **Opt-in speed test** — `--speed-test` + `--min-speed`; capped 8 MiB
    sample per phase-2-passing endpoint. The intent ban on *default* speed
    testing (`docs/intent/cf-scanner.md`) stands.
11. **Neighbor scan** — `--neighbor-scan 0-64`; same-/24 widening through the
    worker channels, obeying cap/target/cancel.

Non-goals confirmed during the audit and left out: default speed tests,
scan history, GUI/Android/Docker, WARP-mode changes.
