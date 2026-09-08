# T-22 — doc-drift-sweep (F-22)

## Gaps (mechanical, docs-only)
- `docs/development.md`: MSRV 1.85 → 1.88; npm bump "conditional" → mandatory;
  document nightly CI trigger; curl-missing troubleshooting row.
- `docs/spec.md` §4/§9: structure listing (8+ modules unlisted, ranges.rs
  flat-ref, api facade split, docs/ listing); HTTPUpgrade-vs-xray claim;
  server-port vestige. Keep the SUPERSEDED banner.
- ADR-010 status → `Superseded by ADR-013`; ADR-005 body scrub
  (frontend/HTTP refs); ADR-008 tokio `fs` feature note.
- Intent doc: annotate superseded claims (IP2Location→db-ip, speed-test ban
  now opt-in, browser/file-download refs) — annotate, don't rewrite history.
- AGENTS.md: add `sharelinks` to export formats.
- `data/geoip-version.txt`: trailing newline.
- GitHub (manual, with PR): repo description drops "browser UI"; close stale
  issue #6; add topics.
- `build.rs`/`xray.rs` nits (read_all error swallow, zip double-read):
  verify-then-fix; if real, fix, else close with evidence.

## Files
Docs listed above (+ `src/xray.rs`/`build.rs` only if nits verify).

## Gates
`cargo test` + `cargo clippy --all-targets -- -D warnings` + `cargo fmt --check`.
