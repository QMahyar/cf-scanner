# T-18 — unit-edge-coverage (F-18)

## Gaps (per-module edge tests; see FINDINGS F-18 for the full list)
- `FakeTransport`: emit `ProbeError::{Timeout,TlsHandshake,…}` in CDN tests.
- `FakeOpener::open` → `Err` path in speed tests.
- `enrich::{lookup,enrich_working}`: add an injectable HTTP seam (trait for
  the fetch, default = real client), then unit-test timeout/429/500/partial/
  empty/all-fail paths offline.
- `util::percent_decode`: empty/no-encode/invalid/multi-byte/non-UTF8.
- `geo::parse_colo`: CRLF, multi `colo=` lines, 4-char garbage, private ranges,
  corrupted-mmdb negative.
- `wgconf`: render edges (empty AllowedIPs, MTU boundary, `mtu=abc`, no PSK),
  wg:// render round-trip, IPv6 zone/long-host.
- `dgst::hex_lower` + multi-SHA2-256-line edges.
- `paths::write_secret` Unix-0600 assertion + poison-guard path.
- `export::write_export` orchestrator test.
- `probe`: HTTP/2 status line, accepted-code filtering, trace→colo path,
  `remark_for` phase2-no-colo, `unique_tag` dedup suffix, `plan_probe_count`.
- `pool`: `/0` host_count boundary, overlapping exclusions, `#` comments, tmp
  naming; `official`: malformed JSON/text, empty arrays, whitespace-only,
  refresh races, atomicity; `retry`: corrupt JSON, concurrent save/load,
  read-only dir, pathological size; `store`: remove-missing, empty merge, colo
  update, ISP truncation; `speed`: cancel mid-download, opener-fail, NaN
  min-speed, empty candidates; `neighbor`: channel-full; `phase2`: unknown
  verifier tag, http:// prefix, sub-spec caps; engine: WARP worker panic,
  mixed OK/Err sequences.

## Fix
Table-driven unit tests per module. May split into 2-3 commits by area
(configs+geo+dgst / engine-speed-neighbor-phase2 / probe-pool-retry-store)
if the diff gets large — still one ticket.

## Files
Test mods across the modules above (+ `src/enrich.rs` seam).

## Gates
`cargo test` + `cargo clippy --all-targets -- -D warnings` + `cargo fmt --check`.
