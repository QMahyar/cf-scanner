# AGENTS.md — CF-Scanner

Single cross-platform Rust binary that finds working Cloudflare IPs/endpoints
on ISP-restricted networks. CDN/proxy mode (TCP/TLS phase-1 scan; xray-backed
phase-2 real-config verification with DPI fragmentation) + WARP mode (UDP
endpoint discovery with WireGuard handshake probes, optional wgconf
verification, opt-in config registration). Localhost HTTP API + embedded
browser UI + CLI, all over one in-process engine.

## Source of truth (read before coding)

- `docs/intent/cf-scanner.md` — confirmed user intent + verified research corrections
- `docs/spec.md` — approved spec (commands, structure, style, boundaries, decisions)
- `docs/development.md` — local build + test flow (incl. dist smoke test + placeholder restore)
- `docs/release-process.md` — versioning control + publishing pipeline (release/tag/fix flows)
- `docs/decisions/` — ADRs (ADR-007 = versioning + publishing decision)
- `tasks/plan.md`, `tasks/todo.md` — implementation plan and task list (Task N references in commits)

## Skills

- Rust work: always load the `rust-engineering` skill (Rust architecture, async,
  ecosystem decisions, review — version-matched best practices) before writing
  or reviewing Rust code here.

## Commands

```
cargo build --release     # build
cargo run -- serve        # dev: API + UI on 127.0.0.1:8765
cargo test                # unit + integration tests
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo audit               # dependency vulnerability scan (cargo install cargo-audit)
dist plan --artifacts=all --tag=v0.1.0   # release dry-run (dist, formerly cargo-dist)
# local packaging smoke test, then restore the tracked 0-byte placeholders:
dist build --artifacts=local --target=<host-target>
git restore data/bundled/xray data/bundled/xray.exe
```

Release flow (tag → CI → GitHub Release) is in `docs/release-process.md` — never publish artifacts manually.

## Architecture

- Single process. CLI, HTTP server, wizard, frontend = thin clients of ONE
  engine (ScanController) and ONE API contract in `src/api/types.rs`.
- Contract first: `src/api/` defines ScanConfig/Verdict/StopCondition/events;
  engine returns domain types; server maps domain → API. Never serialize
  engine types directly.
- Probe transports are injectable (trait) so tests never touch the network.
- xray = subprocess (`xray run -c config.json`, local socks inbound). The
  crates.io `xray-core` crate is ONLY a gRPC client — do not use it to embed.
- Fragment (DPI bypass): `fragment` block on a Freedom outbound +
  `sockopt.dialerProxy` chaining. Presets: light 100-200/10-20, medium
  50-200/10-40, heavy 10-300/5-50 (packets="tlshello").
- WARP probe: boringtun builds Init (valid MAC1 required, MAC2 zeros OK);
  Response (92B, type 2) or Cookie (64B, type 3) + receiver-index match = open.
- Results: last-scan-only, in memory; reset clears. NO history, NO telemetry.
- GeoIP: db-ip Lite mmdb embedded via include_bytes! + maxminddb 0.30
  (geoip2 types built in). Country offline; datacenter = colo from
  /cdn-cgi/trace (phase 2 only). Attribution required (CC BY 4.0, footer link).
- CLI agents: `scan` prints newline-delimited JSON on stdout + final summary.

## Code conventions

- Rust edition 2024, `#![deny(warnings)]` only in CI, `Result<T, anyhow::Error>`
  at boundaries, typed errors internally.
- snake_case; verbs for functions, nouns for types; no comments unless WHY.
- All network-touching async functions take timeouts; every scan loop checks
  stop conditions each iteration.
- Keep tasks S/M sized (≤5 files). API contract changes = ask first.

## Boundaries

- Always: cargo test + clippy -D warnings + fmt --check before committing;
  validate user input (ports, CIDRs, URI schemes); verify `.dgst` checksums
  for downloaded xray binaries; bind 127.0.0.1 unless an explicit flag exists;
  keep configs/keys out of logs.
- Ask first: adding dependencies; changing `src/api/`; dist/release config;
  bundling new binaries/data files; changing default scan behavior.
- Never: log/transmit imported configs or keys; embed secrets; delete tests
  to make CI green; commit xray binaries or mmdb to git; scan ranges other
  than official CF lists, WARP pools, or explicit user input.

## Gotchas

- Termux build = static musl; xray linux-arm64 is glibc (needs Termux glibc
  pkg). Document, don't fix.
- No official /cdn-cgi/trace docs (community endpoint); parse defensively.
- WARP server pubkey: bundle known constant, refresh from registration API.
- Windows binaries unsigned → SmartScreen warning (accepted, documented).
- Dev without release bundles: xray download fallback = pinned GitHub release
  tag from `data/xray-version.txt` + `.dgst` verification into data dir.
