# Implementation Plan: CF-Scanner

## Overview

One Rust binary: localhost HTTP API + embedded browser UI + CLI (flags, wizard,
JSON-lines) over a shared engine. CDN mode (TCP/TLS phase-1 scan; xray-backed
phase-2 real-config verification with DPI fragmentation) and WARP mode (UDP
endpoint discovery with real WireGuard handshake probes, optional wgconf
verification, opt-in config registration). GeoIP offline (db-ip Lite mmdb),
datacenter via /cdn-cgi/trace colo. Release via dist (5-target matrix, msi +
shell + powershell installers, mmdb + xray bundled as ExtraArtifacts).

Source of truth: `docs/spec.md` (approved 2026-08-12) and
`docs/intent/cf-scanner.md`.

## Architecture Decisions

- **Single process, single engine.** CLI and HTTP server share one
  ScanController in-process; the browser and CLI are both thin clients of the
  same API types (`src/api/`). No separate daemon mode.
- **API contract first.** `src/api/types.rs` is the shared contract; server,
  CLI, frontend, and engine all depend on it. Defined before slices built on it.
- **Probe transports injectable.** The scanner talks to a `Probe` trait so
  unit/integration tests never touch the network; real impls: TLS handshake
  probe, UDP WG probe, xray tunnel check.
- **xray as subprocess, not crate.** crates.io `xray-core` is only a gRPC
  client; we spawn the official `xray` binary (`xray run -c config.json`) with
  a local socks inbound. Bundled in release archives (dist ExtraArtifact);
  runtime fallback downloads with `.dgst` checksum verification.
- **Fragment via XTLS documented pattern:** fragment block on a Freedom
  outbound + `sockopt.dialerProxy` on the proxied outbound.
- **WARP probe via boringtun** (valid MAC1 required; MAC2 zeros OK). Response
  (92B, type 2) or Cookie (64B, type 3), structurally valid = open
  (verified live: WARP replies under its own session index, no match).
- **Last-scan-only state.** Results kept in memory; reset clears. No history.
- **JSON-lines CLI.** `scan` prints one JSON object per result + final summary;
  wizard is interactive.

## Task List

### Phase 0: Foundation

- [ ] Task 1: Project skeleton — workspace, Cargo.toml (pinned deps), layout,
      .gitignore, data/ placeholders, PR CI workflow (test/clippy/fmt).
- [ ] Task 2: API contract types (`src/api/types.rs`) + validation.

### Checkpoint A: Foundation
- [ ] `cargo build` clean, `cargo test` green, CI workflow file valid
- [ ] Human review of task list before engine work

### Phase 1: Engine core (CDN phase 1)

- [ ] Task 3: Ranges — bundled cf-ranges.txt, CIDR expansion + sampling
      (presets, custom count), exclusion lists, custom CIDR input.
- [ ] Task 4: TLS probe — tokio TCP connect + TLS handshake, timeout, latency,
      SNI, injectable transport.
- [ ] Task 5: ScanController — stop conditions (N found / cap / run-until),
      worker pool, progress events, results store (last-scan + reset).
- [ ] Task 6: Server API — axum routes (start scan, SSE events, results,
      reset, health), static embed serving.

### Checkpoint B: Phase-1 engine works end-to-end via API + curl
- [ ] Scan runs with presets/custom count/ports/exclusions/stop conditions
- [ ] SSE stream delivers progress; results readable; reset works

### Phase 2: Frontend + CLI

- [ ] Task 7: Frontend `embed/index.html` — Pico.css + htmx + SSE; config form
      (mode/preset/ports/stop), live sortable results table, copy/save/reset,
      db-ip attribution.
- [ ] Task 8: CLI — `serve` / `scan` / `ranges` subcommands; JSON-lines
      output; interactive wizard (mode, phase, count, stop, config import).

### Checkpoint C: Full UX loop works in browser and CLI
- [ ] Browser: configure → scan → live results → copy/save/reset
- [ ] CLI: one-shot scan prints JSON lines; wizard drives same engine

### Phase 3: CDN phase 2 (xray)

- [ ] Task 9: Config parsers — vless/trojan/vmess/ss URIs, subscription URLs,
      Xray JSON → OutboundSpec (normalized).
- [ ] Task 10: Xray manager — bundled binary discovery, checksum-verified
      download fallback, spawn/cleanup, socks inbound configs, fragment preset
      builder (light/medium/heavy/custom → freedom + dialerProxy).
- [ ] Task 11: Phase-2 verifier — swap IP, run xray, tiny HTTP GET through
      tunnel (configurable target), latency, verdict with fragment/SNI combo,
      bounded concurrency.

### Checkpoint D: Phase-2 verdicts against a real xray binary
- [ ] A candidate IP verified through user config; verdict shows fragment+SNI

### Phase 4: WARP

- [ ] Task 12: WARP probe — bundled pools, ports (2408 default), boringtun
      Init, UDP send/recv, Response/Cookie classify, latency + loss, custom
      endpoint list.
- [ ] Task 13: wgconf parse + real-config verification (WireGuard/AmneziaWG),
      endpoint swap, handshake with user keypair.
- [ ] Task 14: WARP registration — v0a884 client (register/enable/fetch),
      keygen, wgconf builder, WARP+ license binding, export text/.conf,
      identity persistence.

### Checkpoint E: WARP end-to-end (discovery → verify → generate → export)

### Phase 5: Geo + integration

- [x] Task 15: Geo — embedded db-ip Lite mmdb (country), maxminddb lookup,
      /cdn-cgi/trace colo parse with fallback.
- [x] Task 16: Engine integration — colo/loss/sort keys wired into verdicts
      and results; sortable columns complete.

### Checkpoint F: Results complete (country/colo/latency/loss, sorting)

### Phase 6: Release + docs

- [x] Task 17: dist config — 5 targets, installers (msi/shell/powershell),
      ExtraArtifacts (mmdb, xray), release.yml, plan verification.
- [x] Task 18: README + ADRs (xray bundling, boringtun, db-ip, fragment chain,
      single-binary UI, no-history), Termux/SmartScreen caveats.
- [ ] Task 19: Final review — code-review-and-quality + code-simplification +
      security pass; fix findings.

### Checkpoint G: v0.1.0 release ready
- [ ] `dist plan --artifacts=all --tag=v0.1.0` green
- [ ] All tests/clippy/fmt green; review findings closed

## Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| xray binary fails to run on Termux (glibc) | Med | Static musl app binary; xray linux-arm64 glibc documented; graceful runtime error with install hint |
| ISP blocks api.cloudflareclient.com during registration | Med | Clear error message; no proxy fallback (user decision); registration is opt-in |
| UDP probes timeout/noisy on filtered networks | Med | N-probe loss measurement, adaptive timeout, Response/Cookie both accepted as open |
| boringtun API drift | Low | Pin 0.7.1; golden Init/Response/Cookie vector tests |
| mmdb embed bloat | Low | Country-only Lite db (~small); exclude City if >5MB |
| rustls cert verification fails on some CF edges | Low | webpki-roots + standard verifier; failure = fail verdict (anti-MITM per spec) |
| Local port collisions (server 8765, xray inbounds) | Low | Port picker with fallback; xray inbounds on ephemeral range 2xxxx+ |
| dist/ExtraArtifact bundling of xray is fiddly | Med | Build script downloads xray + .dgst at release time; document in ADR; runtime fallback covers misses |

## Open Questions

- None blocking. (All spec decisions confirmed 2026-08-12.)
