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
