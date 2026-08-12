# Changelog

All notable changes to CF-Scanner are documented here, grouped by
Added / Changed / Fixed / Deprecated / Removed / Security, newest on top.

## [Unreleased]

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

### Changed
- `stop.cap` may now be smaller than `stop.found` (the cap wins first);
  previously such configs were rejected as invalid.
- `custom_cidrs` now REPLACE the bundled ranges (was: merged in addition);
  exclusions still apply to custom ranges.
