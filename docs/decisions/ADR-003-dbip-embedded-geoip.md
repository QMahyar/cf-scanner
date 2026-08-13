# ADR-003: Embedded db-ip Lite MMDB for country lookup

## Status
Accepted

## Date
2026-08-13

## Context
The results table shows each IP's country. The `maxminddb` crate (0.30, ISC)
reads MMDB only. IP2Location LITE ships CSV/BIN — incompatible. MaxMind's own
GeoLite2 requires an account and license key. The app must stay offline-first:
no runtime geo lookups against external services, single binary.

## Decision
Use db-ip.com Lite (IP-to-Country) MMDB, CC BY 4.0, free, monthly updates.
`build.rs` downloads `dbip-country-lite-<version>.mmdb.gz` (pinned in
`data/geoip-version.txt`), decompresses it, and embeds it via
`include_bytes!` + `Reader::from_source` (static bytes, no mmap). Country is
resolved in-process per verdict. The UI footer links the required
attribution (CC BY 4.0).

## Alternatives Considered

### IP2Location LITE
- Pros: well-known
- Cons: CSV/BIN only; the maxminddb crate reads MMDB only
- Rejected: format mismatch

### MaxMind GeoLite2
- Pros: de-facto standard
- Cons: requires account + license key; not embeddable offline without
  managing secrets
- Rejected: violates no-secrets, offline-first constraints

### Runtime HTTP geo lookup (e.g. ip-api)
- Pros: always fresh data
- Cons: needs network (the very thing being scanned), sends scanned IPs to a
  third party, violates no-telemetry intent
- Rejected

## Consequences
- Database freshness is a build-time property (`data/geoip-version.txt`);
  updating it re-embeds on next build.
- Offline builds embed an empty database and degrade to "unknown country"
  instead of failing.
- The `maxminddb` 0.30 crate has no `geoip2` cargo feature — the geoip2 types
  are built in; the API is `lookup(ip)` → `decode::<geoip2::Country>()`.
- CC BY 4.0 attribution must remain visible in the shipped UI.
