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
- `docs/review/product-review-2026-08-13.md` — finished-product review
  (drove the `review/*` hardening cycle shipped in v0.4.0-v0.5.0; superseded
  findings were re-audited and shipped in v0.5.1)

## Skills

- Rust work: always load the `rust-engineering` skill (Rust architecture, async,
  ecosystem decisions, review — version-matched best practices) before writing
  or reviewing Rust code here.

## Commands

```
cargo build --release     # build
cargo run -- serve        # dev: API + UI on 127.0.0.1:8765 (UI: cd ui && npm ci && npm run build first, or it serves the committed ui/dist)
cargo test                # unit + integration tests
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo audit               # dependency vulnerability scan (cargo install cargo-audit)
dist plan --tag=vX.Y.Z   # release dry-run (dist, formerly cargo-dist)
# local packaging smoke test, then restore the tracked 0-byte placeholders:
dist build --artifacts=local --target=<host-target>
git restore data/bundled/xray data/bundled/xray.exe
```

Release flow (tag → CI → GitHub Release → npm publish, all automatic) is in `docs/release-process.md` — never publish artifacts or the npm package manually.

npm publishing knowledge (AGENTS must know, condensed from `docs/release-process.md`):
- The npm wrapper `@qmahyar/cf-scanner` (`npm/cf-scanner/`) is published by
  the Release workflow's `npm-publish` job (after `host` creates the GitHub
  Release). It needs the `NPM_TOKEN` repo secret (npm automation token) and
  an npm account that owns the `@qmahyar` scope (`npm whoami` → `qmahyar`).
- Missing `NPM_TOKEN` = job dies with `ENEEDAUTH need auth` — set it with
  `gh secret set NPM_TOKEN`, then re-run the failed job or re-push the tag.
- The token is a 90-day npm automation token (no 2FA). Expiry shows up as
  `ENEEDAUTH`/E401 despite the secret existing — then ask the USER for a
  fresh token, run `gh secret set NPM_TOKEN`, re-run; never try to publish
  around it.
- The package exists on the registry since 2026-08-17 (0.4.0 first) — publish
  updates it in place; there is no claim step.
- `RELEASE_TAG` in `npm/cf-scanner/install.js` must equal the released tag
  (the workflow greps it); npm `version` is registry bookkeeping only.
- npm refuses republishing the same version and unpublish is blocked 24h —
  a broken npm release is fixed with a PATCH bump, never a delete.
- Manual `npm publish` is only for documented emergencies (see the doc);
  users install via `npm i -g @qmahyar/cf-scanner`.

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
  open = shape-only classification: Response (92B, type 2) or Cookie (64B,
  type 3) from the probed endpoint. No receiver-index match — Cloudflare
  answers dummy-key probes with its own session index (verified live
  2026-08-13).
- Results: last-scan-only, in memory; reset clears. NO history, NO telemetry.
- GeoIP: db-ip Lite mmdb embedded via include_bytes! + maxminddb 0.30
  (geoip2 types built in). Country offline; datacenter = colo from
  /cdn-cgi/trace (phase 2 only). Attribution required (CC BY 4.0, footer link).
- CLI agents: `scan` prints newline-delimited JSON on stdout + final summary.

## Code conventions

- Rust edition 2024, clippy `--all-targets -- -D warnings` in CI (no
  crate-level `#![deny(warnings)]`), `Result<T, anyhow::Error>`
  at boundaries, typed errors internally.
- snake_case; verbs for functions, nouns for types; no comments unless WHY.
- All network-touching async functions take timeouts; every scan loop checks
  stop conditions each iteration.
- Keep tasks S/M sized (≤5 files). API contract changes = ask first.

## Boundaries

- Always: cargo test + clippy -D warnings + fmt --check before committing;
  validate user input (ports, CIDRs, URI schemes); verify `.dgst` checksums
  for downloaded xray binaries; bind 127.0.0.1 only, port configurable via
  `--port`; keep configs/keys out of logs.
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
