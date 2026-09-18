# 01: WARP pool 8 → 15 /24s

**What to build:** the WARP scan draws candidates from 15 probe-verified /24s instead of 8, so scans cover the endpoint space both competitor scanners already ship. Sampling behavior and totals math stay consistent (no test or count drifts).

**Blocked by:** None (can start immediately).

**Status:** done

Spec: `../spec-best-in-class.md` §P0-1. Inherits spec §6 execution rules.

- [x] The 7 missing /24s (6.x–8.x blocks per spec) are appended to the bundled WARP pool; `162.159.193.0/24` is kept
- [x] Pool-size-derived test expectations updated alongside; `cargo test` green
- [x] No contract change; sampling math unchanged; CDN ranges untouched (official-only boundary holds)
- [x] `cargo clippy --all-targets -- -D warnings` + `cargo fmt --check` green

## Result

Files changed (3, all in scope):
- `data/warp-pools.txt`: 8 → 15 lines; added `8.6.112.0/24, 8.34.70.0/24,
  8.34.146.0/24, 8.35.211.0/24, 8.39.125.0/24, 8.39.204.0/24, 8.39.214.0/24`
  (exact spec §P0-1 set). `162.159.193.0/24` kept. New entries inserted before
  `8.47.69.0/24` so the file's pre-existing numeric-ascending order is
  preserved; trailing newline preserved (verified byte-level).
- `src/warp.rs:478`: `bundled_pools_cover_the_known_endpoint_space`
  expectation `8 * 256` → `15 * 256`.
- `src/engine/warp.rs:494`: `warp_full_pool_scan_visits_every_endpoint`
  expectation `8 * 256` → `15 * 256`.

Behavior: WARP scans draw candidates from 15 probe-verified /24s (3840 hosts);
sampling math, contracts, and CDN ranges untouched. No new deps, no
dist/release/version changes. `rust-engineering` skill unavailable in this
session; proceeded per spec §6 + AGENTS.md v0.8.0 invariants.

Gate evidence:
- `cargo test --lib bundled_pools_cover_the_known_endpoint_space` →
  `test result: ok. 1 passed; 0 failed`
- `cargo test --lib warp_full_pool_scan_visits_every_endpoint` →
  `test result: ok. 1 passed; 0 failed`
- `cargo test warp --lib` → `67 passed; 0 failed`; `cargo test pool --lib` →
  `54 passed; 0 failed`
- Full `cargo test` → `651 passed; 2 failed`; both failures are
  `probe::tests::tls_budgets_split_quarter_then_half_remainder` and
  `probe::tests::tcp_probe_refused_keeps_reason` in `src/probe.rs`, which has
  234 lines of uncommitted parallel-ticket (P0-2) edits and zero references to
  warp pools (`bundled_pool|warp` grep: no matches) — pre-existing,
  out-of-scope, left untouched.
- `cargo clippy --all-targets -- -D warnings` → `Finished dev profile`,
  exit 0.
- `rustfmt --edition 2024 --check src/warp.rs src/engine/warp.rs` → exit 0.
  Repo-wide `cargo fmt --check` reports diffs only in `src/probe.rs:780,796,820`
  (parallel ticket's file); `cargo fmt` (write mode) deliberately NOT run —
  it would reformat out-of-scope files owned by a parallel ticket.
- No tests added, none deleted.
