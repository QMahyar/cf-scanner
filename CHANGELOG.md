# Changelog

All notable changes to CF-Scanner are documented here, grouped by
Added / Changed / Fixed / Deprecated / Removed / Security, newest on top.

## [0.4.0] - 2026-08-16

Review-driven hardening from the
[finished-product review (2026-08-13)](docs/review/product-review-2026-08-13.md).
Changes merged by the `review/*` branches land here.

### Security
- Host-header allowlist + Origin/Sec-Fetch-Site checks close the
  DNS-rebinding/CSRF/SSRF surface of the unauthenticated localhost API.
- Phase-2 configs over the HTTP API accept URLs/URIs only; local file paths
  stay CLI-only.
- Profile responses mask WireGuard key material.
- Trial xray configs written 0600; stale `trial-*` dirs swept on startup.
- Trial config directories are removed on drop even when the attempt dies
  mid-flight (cancel, shutdown) — plaintext-credential configs never survive
  on disk.
- xray stderr is masked against the trial config's credentials (user ids,
  passwords, fronting SNI/Host) before it is logged or surfaced; error text
  is sanitized (URL userinfo/query stripped, lines capped).
- The WARP identity file is written 0600 (owner-only) atomically (temp +
  rename), so the private key is never world-readable, not even for a
  microsecond.
- List fields (ports, SNIs, exclusions, CIDRs) capped and deduped.

### Performance
- Bounded probe fan-out: a worker pool drains the plan instead of spawning a
  task per (host, port); `Preset::Full` can no longer OOM the process.

### Reliability
- xray lifecycle: graceful shutdown reaps children, fast corrupt-binary
  detection, stderr surfaced (redacted), single pre-flight download.
- Cancelling a scan now stops phase-2 verification too: one cancel signal is
  shared across phases, so a cancel fired during phase 1 (or in the gap
  before phase 2) halts tunnel probes immediately instead of leaving them
  running.
- The event stream re-syncs against the results store: a consumer that fell
  behind (dropped events) is re-served the verdicts it missed at end of run,
  deduplicated by endpoint, so results are never permanently lost.
- With phase 2 enabled, the found-count summary reflects verified working
  endpoints — candidates that failed verification no longer count as found.
- Zero-candidate scans no longer destroy results; run failures surface
  instead of hanging the UI.
- Bundled xray is size-checked so a corrupt or placeholder binary fails fast
  with a clear error instead of a confusing run failure.

### Changed
- WARP input validation: `--preset` and `--custom-cidrs` are rejected for
  WARP scans (both are CDN-only concepts — WARP takes `--count` +
  `--warp-endpoints`); duplicate endpoints and ports are deduped so no
  endpoint is probed twice.
- Dense IPv4 blocks (/24 and tighter) sample only real hosts — network and
  broadcast addresses are skipped.
- The WARP server public key is persisted at registration and preferred over
  the bundled constant, so probes keep working if Cloudflare rotates it.
- VMess `alterId` and AEAD `security` settings pass through to the xray
  config; `reality` security is rejected up front with a clear error (the
  builder cannot emit a working reality outbound).
- Phase-2 fragment wiring is gated: the `dialerProxy` chain is only attached
  when a fragment outbound actually exists, so a custom preset with no
  values can no longer produce a config xray refuses to run.

### UI
- Scan-state machine rework: real "Cancelled" state, start/reset guards,
  live-region + progressbar accessibility fixes, light-theme contrast pass,
  SSE reconnect/recovery.

### Docs
- spec.md flipped to APPROVED; stack/structure/testing corrections.
- README customer quickstart; docs index + QA runbook; task-tracker
  reconciliation.

### Added
- Property-test suites (proptest) for the config/URI parsers, wgconf, and
  the chunked-transfer decoder; `decode_chunked` now has bounds tests
  (huge sizes, truncation, malformed streams).
- CLI: WARP scans without `--count` now default to the full bundled pool;
  `--phase2-only` and `--cap 0` are rejected up front; `--phase2-custom`
  requires `--phase2-configs` + a custom fragment preset.
- API: `/api/warp/register` is rate-limited (1 per 60 s) and refuses to
  replace an existing identity unless `overwrite:true` is sent — the UI
  retries once with consent on a 409.
- API: custom CIDRs/endpoints that are non-routable (loopback, link-local,
  unspecified, RFC1918, ULA) are rejected with a 400; the CLI stays
  unrestricted.
- WARP scans driven over the API use the canonical WARP port set when the
  caller left the default port.

### Changed
- CLI: wizard prose moved to stderr (the wgconf export stays on stdout);
  Ctrl+C during the wizard exits 0; a closed output pipe cancels the scan
  instead of panicking; `shutdown_signal` no longer parks forever.
- Server: an SSE consumer that falls irrecoverably behind is disconnected
  instead of being replayed a stale run; a client connecting after a run
  ended gets exactly one terminal event replayed (tagged by run epoch).
- UI: toast auto-dismiss works under reduced motion; the progress title is
  throttled; IPv6 sorts correctly; a new run's generation guard stops
  replayed terminal events from older runs; loading a profile no longer
  clobbers user-configured ports; results sort by latency by default with
  missing values last; reconnect refreshes progress.
- CI: the release workflow attests artifacts (`id-token`/`attestations`
  permissions), its gate runs test + clippy + fmt + audit and blocks the
  host job; checks run on Windows too; a parity job fails fast if the
  pinned xray release disappears; the MSI ships the MIT license; rust-cache
  re-added.
- Test fixtures no longer carry real credentials (UUIDs/private keys
  replaced with inert zeroed values).

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

[0.4.0]: https://github.com/QMahyar/cf-scanner/releases/tag/v0.4.0
[0.3.0]: https://github.com/QMahyar/cf-scanner/releases/tag/v0.3.0
[0.2.0]: https://github.com/QMahyar/cf-scanner/releases/tag/v0.2.0
[0.1.0]: https://github.com/QMahyar/cf-scanner/releases/tag/v0.1.0
