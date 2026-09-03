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
