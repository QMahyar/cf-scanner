# Changelog

All notable changes to CF-Scanner are documented here, grouped by
Added / Changed / Fixed / Deprecated / Removed / Security, newest on top.

## [Unreleased]

### Added
- Development + release process docs (`docs/development.md`,
  `docs/release-process.md`, ADR-007) so future developers and agents follow
  one local build/test flow, versioning contract, and publishing pipeline.

## [0.1.0] - 2026-08-13

### Added
- Project skeleton: CLI entry (serve/scan/ranges), CI checks workflow,
  bundled Cloudflare IPv4 ranges + WARP endpoint pools + pinned xray version.
- API contract types (`ScanConfig`, `StopCondition`, `Verdict`, `ScanEvent`)
  with input validation.
- Ranges engine: CIDR parsing/normalization, exclusion subtraction, preset
  and count sampling plans, `ranges refresh` via verified HTTPS fetch.
- Phase-1 probe transport: injectable TCP+TLS latency probe (no cert
  verification by design; real validation lands with phase-2).
- Scan controller: stop conditions (N found / hard cap / run-until),
  concurrency-limited fan-out, SSE-style event stream (progress/results/
  finished), latency-sorted results store, cancellable runs, last-scan-only
  semantics. Phase-2/WARP modes explicitly rejected until Tasks 11/12.
- Local HTTP server (axum) on 127.0.0.1: scan start, SSE event stream,
  results+summary, cancel, reset, ranges, embedded placeholder UI.
- Phase-2 config parsers: `vless://`/`trojan://`/`vmess://`/`ss://` URIs,
  subscription URLs, and Xray JSON → normalized outbound spec.
- Phase-2 verification engine: spawns the official xray binary
  (`xray run -c config.json`, local socks inbound), DPI-bypass fragmentation
  (light/medium/heavy/custom presets via freedom outbound +
  `sockopt.dialerProxy`), per-IP verdicts with SNI/fragment details.
- WARP mode engine: UDP endpoint discovery with real WireGuard handshake
  probes (boringtun), optional wgconf verification, opt-in client registration
  via Cloudflare's API + wgconf export.
- GeoIP: db-ip.com Lite country MMDB embedded at build time; country and
  datacenter (colo) shown in results and sortable in the UI (CC BY 4.0).
- Release pipeline: cargo-dist with msi/shell/powershell installers, 5-target
  matrix, and the xray binary bundled into every archive (checksum-verified at
  build time).
- README, docs/decisions ADRs (xray bundling, boringtun, db-ip, fragment
  chain, single-binary contract, no-history/no-telemetry).

### Changed
- `stop.cap` may now be smaller than `stop.found` (the cap wins first);
  previously such configs were rejected as invalid.
- `custom_cidrs` now REPLACE the bundled ranges (was: merged in addition);
  exclusions still apply to custom ranges.
