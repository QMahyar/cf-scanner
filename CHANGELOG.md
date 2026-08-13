# Changelog

All notable changes to CF-Scanner are documented here, grouped by
Added / Changed / Fixed / Deprecated / Removed / Security, newest on top.

## [0.3.0] - 2026-08-13

### Added
- `GET /api/status` endpoint returning server version and scan state.
- Frontend loads scan results on page refresh via `/api/results`.
- Toast notification system for user feedback (copy, download, profile
  save/delete).
- Download dropdown with TXT/CSV/JSON formats and timestamped filenames.
- Empty results table shows a centered CTA instead of a blank row.
- Status card shows ETA and "X of Y scanned" during scan.
- Retry button on scan failure.
- Skip-to-content link and screen-reader-only live regions for result
  count and sort announcements.
- Keyboard-operable sort headers (Enter/Space).

### Changed
- Embedded frontend typography: rem-based sizing, tabular-nums on
  numeric columns, 3-state theme toggle (Auto/Light/Dark), spacing
  token system, compact 48px header with backdrop blur and GitHub link.
- Form improvements: inline help text, Ctrl+Enter shortcut, disabled
  field explanations, field error styling.
- Data table: right-align numeric columns, default sort by latency,
  sticky first column support, tabular-nums on mono cells.
- Progress bar: 8px height, ease-out transition, auto-scroll on
  completion.
- Clipboard copy: icon swap to checkmark on success, aria-live toast
  on success/failure.
- Reset button confirms before clearing results when data exists.
- Download filenames use `cf-scanner-{mode}-{ISO8601}.{ext}` pattern.
- Profile storage sanitizes WarpConfig to strip `generate_config` and
  `warp_plus_license` before persisting.
- API error responses now return structured JSON instead of plain text.

### Fixed
- `ranges` endpoint no longer includes `bundled` field (unused by frontend).
- Theme button aria-label mismatch (removed redundant label).
- `prefers-reduced-motion` now selectively disables animations instead of
  blanket-removing all transitions.
- `forced-colors` support for progress bars, segmented controls, and
  focus outlines.

## [0.2.0] - 2026-08-13

### Added
- IPv6 candidate ranges in phase 1: official Cloudflare v6 list bundled
  (`data/cf-ranges-v6.txt`), `--ipv6` CLI flags, `ScanConfig.include_v6`
  toggle, IPv6 verdicts (wire-compatible `IpAddr`), v6 exclusions/sampling.
- Background ranges refresh (24h, non-blocking, failure keeps last-good data)
  and `last_updated` (RFC3339 UTC) on `GET /api/ranges`.
- In-memory scan profiles API (`GET/PUT/DELETE /api/profiles[/{name}]`,
  session-lifetime, validated configs, no persistence).
- UI: dark mode (system + manual toggle), results density toggle, latency
  histogram, fragment preset editor (custom fields), client-side CSV/JSON
  results export, WARP wgconf import (paste + file picker), profiles panel,
  ranges last-updated display, IPv6 checkbox.
- Development + release process docs (`docs/development.md`,
  `docs/release-process.md`, ADR-007) so future developers and agents follow
  one local build/test flow, versioning contract, and publishing pipeline.
- Post-v0.1.0 roadmap in `tasks/plan.md` (Phase 7 candidate tasks).
- `cargo audit` dependency scan as a mandatory CI check (was local-only).

### Changed
- Release archives now carry only the target platform's xray binary; the
  foreign 0-byte placeholder is dropped at build time.
- CI checks updated to `actions/checkout@v6` (Node 20 deprecation).
- `ScanTarget::Count` is capped at 100 000 (an unauthenticated scan request
  could otherwise allocate gigabytes and abort the process).

### Fixed
- `GET /api/profiles/{name}` now exists; the UI's Load button previously
  404'd because the route only handled PUT/DELETE.
- A panicking scan run no longer permanently bricks the controller: the
  busy flag and cancel slot are reset via a RAII guard, and mutex poisoning
  is tolerated everywhere.
- IPv6 ranges refresh is atomic (temp file + rename) with a last-updated
  header, matching the v4 refresh (torn reads could fail concurrent scans).
- IPv6 entries are dropped from the IPv4 refresh feed (a v4-only scan could
  otherwise silently scan v6 hosts); v6 `/0` custom ranges are rejected with
  a clear error instead of producing off-by-one exclusion math.
- CSV export neutralizes spreadsheet formula injection (`=`, `+`, `-`, `@`
  lead-ins); copied/saved endpoints bracket IPv6 addresses (`[::1]:443`).

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
