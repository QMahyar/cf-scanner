## Question

How do we enrich results with ASN/ISP metadata so users on ISP-restricted
networks can pick endpoints that bypass their ISP's DPI?

## Scope

**Gap**: SenPaiScanner merges Cloudflare trace, IPWhois, IPinfo, and Team
Cymru DNS for ASN/ISP per result. CF-Scanner has offline GeoIP country +
phase-2 colo only. Country-only is insufficient for DPI-bypass decisions.

**Design options** (ticket resolves which):
1. **Online enrichment** (opt-in `--enrich-asn`): query `speed.cloudflare.com/meta`
   or Team Cymru DNS for ASN per working IP after scan completes. Adds network
   dependency but only for working IPs (small N).
2. **Offline ASN MMDB**: bundle a second MMDB (db-ip Lite ASN?). Doubles the
   embedded DB size; check license (CC BY 4.0 attribution already in place).
3. **Trace-endpoint ASN**: parse ASN from `/cdn-cgi/trace` response (contains
   `ip=` and sometimes ASN hints — verify what fields are actually present).

**Constraints**:
- Must not slow down the scan loop (enrich after, not during)
- Must work offline by default (enrichment is opt-in or best-effort)
- Must not add telemetry (enrichment queries go to public endpoints, not ours)

## Acceptance

- [ ] Decision recorded: which enrichment source(s)
- [ ] ASN/ISP appears in verdict (new optional fields with `#[serde(default)]`)
- [ ] ASN/ISP appears in CSV export (appended columns, old order preserved)
- [ ] ASN/ISP appears in `--verbose` output
- [ ] Offline default unchanged (no enrichment unless opted in)
- [ ] Tests: enrichment parsing unit-tested with fixtures (no network)
- [ ] `cargo test` + `cargo clippy --all-targets -- -D warnings` +
      `cargo fmt --check` all pass

## Boundaries

- No telemetry — enrichment queries are user-initiated, results stay local
- New `ScanConfig`/`Verdict` fields need `#[serde(default)]`
- API contract changes = ask first (Verdict is part of the contract)
