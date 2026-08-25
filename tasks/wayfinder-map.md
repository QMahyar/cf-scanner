# Wayfinder Map — v0.7.0 Review Remediation → Release v0.8.0

## Destination

All deduplicated findings from the 2026-08-24 ten-agent review implemented,
tested (cargo test/clippy/fmt + UI build), visually verified (Playwright +
visual-qa subagent), and shipped as **v0.8.0** via the standard tag→CI→Release→npm
pipeline. Follow-through refinements (server split, data-write gate,
library facade, Windows xray coverage, SBOM) landed on `main` post-release
as `0.8.x` unreleased work.

## Notes

- Rust work per AGENTS.md. No new dependencies (std/tokio primitives only).
- API contract changes authorized by user for this effort (additive/tightening only).
- Tracker = local markdown (this file). Claims recorded in "Decisions so far".
- Contradiction rulings are decisions, listed here once.

## Decisions so far

- [D1 Engine uses api types directly](#d1): KEEP per ADR-011 — intentional
  boundary, documented; no domain-split refactor.
- [D2 probe_url http:// vs validate_fetch_url mismatch](#d2): INTENTIONAL —
  probe_urls are fetched *through the tunnel* (not SSRF surface); ranges fetches
  are direct. Document in both sites, change nothing.
- [D3 serde(other) on Mode/Preset enums](#d3): SKIP — serde's "unknown variant"
  error is strictly more informative than a silent fallback variant. Locked by
  ADR-012.
- [D4 SBOM/cosign](#d4): PARTIAL — SBOM shipped via `cargo-sbom` in
  `release.yml:build-global-artifacts` (ADR-012). Cosign remains out of scope:
  XTLS publishes checksums, not signatures.
- [D5 AppState split / DataDir single-writer / lib.rs pub(crate)](#d5):
  IMPLEMENTED 2026-08-25 as `src/server/{mod,state,error,guard,sse}.rs`,
  `paths::data_write_guard()` serializing all managed data-dir writes,
  and `src/lib.rs` hiding `geo`/`socks`/`inline_verify`. See commits
  `7246037`, `8d701f9` (all gates green).
- [D6 Windows xray lifecycle](#d6): IMPLEMENTED 2026-08-25 as
  `tests/xray_lifecycle_windows.rs` — `rustc`-compiled fake xray, kill
  verification, trial-dir cleanup, stable across 3 runs. Closes the
  `xray_lifecycle.rs` Unix-only gap.
- [D7 CI toolchain selection](#d7): IMPLEMENTED 2026-08-25 — action ref
  `dtolnay/rust-toolchain@1.88` with explicit `rustup component add` steps;
  `env.TOOLCHAIN` indirection removed after it broke the windows leg.

## Tickets (scored 10 = must-ship now, 1 = cosmetic) — all shipped

### Stream A — Rust core (owner: main session) ✓

| # | Ticket | Score | Files |
|---|--------|-------|-------|
| A1 | Cap wgconf file read at MAX_WGCONF_BYTES before parse | 9 | main.rs |
| A2 | Zip-bomb guard: cap xray zip entry size (64 MiB) pre-extract | 9 | xray.rs |
| A3 | merge_sorted O(found²) → dirty-flag sort-on-read | 8 | engine/mod.rs |
| A4 | Cache WARP server_public_key per scan + warn on corrupt identity fallback | 9 | warp.rs, engine/warp.rs |
| A5 | Kill await-under-Mutex socket cache: inject SocketCache, lock never across .await | 8 | warp.rs, engine/warp.rs |
| A6 | Per-worker task queues (drop Arc<Mutex<Receiver>>), producer send().await, hoist RNG | 7 | engine/cdn.rs, engine/warp.rs |
| A7 | Unify cancel signal (warp reuses controller channel); select! cancel over in-flight probes | 7 | engine/* |
| A8 | SSE resilience: broadcast 1024→4096, replay missed results on Lagged instead of closing | 7 | engine/mod.rs, server.rs |
| A9 | Origin "null" denied; JsonBody rejection sanitized+truncated | 8 | server.rs |
| A10 | Validation tightening: custom_endpoints cap, fragment Custom requires params, raw-array precheck, profile-name traversal, sip002 uid cap, wgconf endpoint host grammar | 7 | api/types.rs, server.rs, configs.rs, wgconf.rs |
| A11 | Panic-safety: ctrl_c Err logged, inline_verify expects→Err, bundled-parse try_fallback, GetTokenInformation buffer check | 6 | main.rs, cli_wizard.rs, inline_verify.rs, ranges.rs, warp.rs, paths.rs |
| A12 | Error mapping: WarpRegisterError typed (502/429/504), sanitize reg body, phase2 empty-reason fix, port-kind context, errno debug log | 6 | warpgen.rs, server.rs, engine/phase2.rs, verify.rs, probe.rs |
| A13 | Boundary validation unify: delete dup checks in main/server, keep cfg.validate() single source | 5 | main.rs, server.rs |
| A14 | HTTP stack: LazyLock reqwest Client shared, ranges fetch via reqwest w/ validating redirect policy, drop hand-rolled TLS fetch, drop blocking feature (tray test-only → gate) | 6 | ranges.rs, xray.rs, tray.rs, Cargo.toml |
| A15 | Blocking-IO hygiene: effective_pool cached/spawn_blocking, tokio fs feature, trial-dir sweep once per phase, TrialDirGuard drop off-thread, wait_for_socks backoff, TCP_NODELAY | 6 | ranges.rs, verify.rs, xray.rs, Cargo.toml, Cargo.lock |
| A16 | Micro-perf: BATCH_FLUSH 256, channel ×4, verdict clone reduction, xray memo invalidation on spawn failure | 5 | engine/mod.rs, cdn.rs, xray.rs |
| A17 | API polish: ErrorResponse.code field, xray/download envelope, SSE phase2-progress rename, retry field | 6 | server.rs, api/types.rs |
| A18 | deny_unknown_fields on ScanConfig/Phase2/Warp payloads | 6 | api/types.rs |
| A19 | CLI UX: help_heading groups, --cap/--target aliases, serve --open, wizard summary+spawn_blocking, TTY progress ticker, after_help examples, --warp-wgconf alias, --json-errors | 6 | main.rs, cli_wizard.rs, tray.rs |
| A20 | dgst strict line parse + edge tests | 4 | dgst.rs |

### Stream B — Frontend (owner: subagent B) ✓

| # | Ticket | Score |
|---|--------|-------|
| B1 | EventSource lifecycle: store/close handle, onDestroy, re-hydrate status/results on reconnect + offline banner | 8 |
| B2 | Font subsets: import latin-only variable subsets | 4 |
| B3 | A11y: aria-describedby field errors + focus-first-invalid, aria-sort on buttons, checkbox focus ring, copy role=status, sticky-bar safe-area | 6 |
| B4 | UX: pace wall-clock tick, Copy-all respects filters | 4 |
| B5 | tsconfig strict:true — attempt, timeboxed; revert if error count > 25 | 4 |

### Stream C — Build/CI/npm/docs (owner: subagent C) ✓

| # | Ticket | Score |
|---|--------|-------|
| C1 | npm install.js: sha256 verification, spawnSync argv (no shell strings), engines >=14.14, download retry ×2, repo casing | 9 |
| C2 | build.rs: curl --retry + tls1.2 proto parity, unknown-xray-target warn→exit(1) | 7 |
| C3 | rust-toolchain.toml pin 1.88 (=CI); Cargo.toml rust-version stays 1.85 floor | 5 |
| C4 | CI: DRY toolchain env, cargo-audit cached install, curl retry on xray-parity, version-parity job (Cargo.toml == package.json == RELEASE_TAG) | 6 |
| C5 | Docs: CHANGELOG newest-top + dedupe Fixed headings; spec/intent frontend+language drift notes; stale comments (server.rs profiles, api/mod.rs, warp.rs pool comment) | 6 |

### Verification & Release (main session) ✓

| # | Ticket | Score |
|---|--------|-------|
| V1 | Full gates: cargo test + clippy -D warnings + fmt --check + ui build | 10 |
| V2 | New tests for every tightened validation + perf invariants (sorted store, queue equivalence, cancel latency, register mapping, dgst edges, SocketCache eviction) | 7 |
| V3 | Visual QA: serve + Playwright self-check + visual-qa subagent pass | 8 |
| V4 | Release: bump 0.7.0→0.8.0 (Cargo.toml, npm package.json, RELEASE_TAG), CHANGELOG section, commit, tag v0.8.0, push, watch CI → GitHub Release → npm publish | 10 |

### Follow-through after v0.8.0 (2026-08-25, unreleased on main) ✓

| # | Ticket | Files |
|---|--------|-------|
| F1 | Data-write gate + library facade | `src/paths.rs`, `src/lib.rs`, `src/server/state.rs`, `src/ranges.rs`, `src/warpgen.rs`, `src/xray.rs` |
| F2 | Server god-file split | `src/server/{mod,state,error,guard,sse}.rs` |
| F3 | Windows xray lifecycle (`rustc`-compiled fake) | `tests/xray_lifecycle_windows.rs` |
| F4 | ADR-012 + SBOM in release | `docs/decisions/ADR-012-*`, `.github/workflows/release.yml` |
| F5 | CI toolchain ref fix (env→@1.88, components via rustup) | `.github/workflows/{checks,release}.yml` |

## Not yet specified (fog)

None — every ticket from this map has been specified, implemented, and
verified. New work starts a fresh map.

## Out of scope

- Domain/engine type split (ADR-011 intentional, re-locked by ADR-012).
- serde(other) enum fallbacks (ADR-012).
- Cosign verification of XTLS `.dgst` (no signatures to verify).
