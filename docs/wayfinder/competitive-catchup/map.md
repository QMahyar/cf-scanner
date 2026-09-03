# wayfinder:map — Competitive catch-up (CDN-mode features)

## Destination

Ship the 11 feature gaps found in the 2026-09-03 competitor audit
(SenPaiScanner, XIU2 cfst, Morteza CFScanner, CrimsonCF, Waldon) as opt-in
additions to the existing CDN scan path — new probes, new filters, richer
verdicts and exports, extended transport verification — without changing
default behavior, without touching WARP mode, and without adding download/
upload speed tests as a default path. Each feature lands green
(`cargo test` + `cargo clippy -D warnings` + `cargo fmt --check`).

## Notes

- Effort mode: **AFK execution** (user directed "do 1 to 11"). Each ticket is
  implemented on its own branch and merged back; tickets are resolved by
  subagents, verified by the driver.
- **No worktrees.** Plain branches only, one checked out at a time. Branches
  are created sequentially from the latest `main`, so merges stay clean.
- Rust work: consult the `rust-engineering` skill. Contract changes touch
  `src/api/types.rs` — keep `deny_unknown_fields` semantics, add
  `#[serde(default)]` to new optional request fields.
- Boundaries: never log/transmit configs or keys; keep new features
  opt-in (no change to default scan behavior); CDN mode only.
- Verification per merge: `cargo test`, `cargo clippy --all-targets -- -D
  warnings`, `cargo fmt --check`.
- F10 conflicts with `docs/intent/cf-scanner.md` (speed tests explicitly
  excluded). Implemented as opt-in `--speed-test` flag, off by default,
  capped download sample — the intent ban on *default* speed testing stands.

## Decisions so far

<!-- one line per closed ticket -->

- [01: Packet-loss rate](tickets/01-loss-rate.md): Verdict carries sent/received/loss_pct; `--loss-threshold` drops lossy results; above-threshold dropped not stored. Shipped with 03+08 in one branch.
- [02: Colo filter at scan time](tickets/02-colo-filter.md): `--colo IATA,...`; unknown-colo passes with one-time warning; exclusion enforced in phase2 where colo becomes known.
- [03: Per-IP phase-1 failure reason](tickets/03-failure-reason.md): `fail_reason` stored as `refused|timeout|tls_failed`; failures stored, `None` latency sorts last, never counted as found.
- [04: Richer CSV columns](tickets/04-csv-columns.md): header is now 11 cols + `speed_test_mbps` at index 7 (F10 ordering); schema test pins the exact string.
- [05: HTTPing probe mode](tickets/05-http-probe.md): `--probe tcp|tls|http` + `--http-status-code`; HttpTransport GETs /cdn-cgi/trace, captures phase-1 colo; CDN-only.
- [06: Share-link rewriting export](tickets/06-sharelinks-export.md): `--export-format sharelinks` reuses rewrite_uris; own format group.
- [07: Latency lower bound](tickets/07-min-latency.md): `--min-latency` drops below-bound verdicts entirely; CLI-only, wizard untouched.
- [08: Idle-hold stability probe](tickets/08-idle-hold.md): `--idle-hold-ms` (0=off); handshake-only latency; RST-after-idle → `Refused("idle-hold RST")`.
- [09: gRPC / XHTTP transport verification](tickets/09-grpc-xhttp.md): parse + xray + sing-box/clash for grpc/xhttp-splithttp; vmess/vless/sip002 + xray-JSON round-trips. HTTPUpgrade deferred (parse-only, no verify).
- [10: Post-stop shortlist speed test](tickets/10-speed-test.md): opt-in `--speed-test` + `--min-speed`; 8 MiB cap via xray tunnel; `speed_test_mbps` on Phase2Verdict + CSV col 7. Intent ban on default speed testing stands.
- [11: Neighbor scanning](tickets/11-neighbor-scan.md): opt-in `--neighbor-scan 0-64`; NeighborHub side channel + inflight counter; neighbors obey cap/target/cancel.

## Not yet specified

- Post-merge integration review of the whole branch set on `main`.
- Whether F9 (grpc/xhttp) should also parse HTTPUpgrade (currently scoped to
  grpc + xhttp only; HTTPUpgrade decided inside the ticket).

## Out of scope

- Download/upload speed tests as a default scan behavior (intent doc; F10 is
  opt-in only, gate revisited there).
- Scan history / dated result files (intent: last-scan-only).
- GUI / Android / Docker / web (ADR-012/013: pure CLI).
- WARP-mode changes (WARP already unique; audit gaps are CDN-side).
