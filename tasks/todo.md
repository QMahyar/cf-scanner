# CF-Scanner — Task List

Status legend: [ ] todo · [~] in progress · [x] done

## Phase 0: Foundation
- [x] Task 1: Project skeleton (Cargo.toml, layout, .gitignore, PR CI)
- [x] Task 2: API contract types + validation

**Checkpoint A:** build clean, tests green, human review of plan

## Phase 1: Engine core
- [x] Task 3: Ranges (bundled CF, presets, exclusions, custom CIDR)
- [x] Task 4: TLS probe (tokio-rustls, latency, injectable)
- [x] Task 5: ScanController (stop conditions, pool, events, results store)
- [x] Task 6: Server API (axum, SSE, static embed)

**Checkpoint B:** phase-1 end-to-end via API (verified live: scan → 8 real
working CF IPs via curl, latency-sorted, with summary)

## Phase 2: Frontend + CLI
- [x] Task 7: Frontend embed (single-file HTML, vanilla JS + native
      EventSource, custom design system, sortable table)
- [x] Task 8: CLI (serve/scan/ranges, JSON lines, wizard)

**Checkpoint C:** full UX loop in browser + CLI (phase-2 fields in CLI, wizard,
and browser form)

## Phase 3: CDN phase 2
- [x] Task 9: Config parsers (URIs, subscriptions, Xray JSON)
- [x] Task 10: Xray manager (bundle, checksum, spawn, fragment builder)
- [x] Task 11: Phase-2 verifier (tunnel HTTP check, verdict)

**Checkpoint D:** phase-2 verdicts with real xray

## Phase 4: WARP
- [x] Task 12: WARP probe (pools, ports, boringtun, loss)
- [x] Task 13: wgconf parse + real-config verification
- [x] Task 14: WARP registration (v0a884, wgconf builder, WARP+, export)

**Checkpoint E:** WARP end-to-end
(verified live 2026-08-13: probe against real endpoints → 162.159.192.5:2408
open; 183/204 open in a 300-candidate run; found stopped at ~2×concurrency
waves — soft-stop overshoot, known behavior; verify path proven by a real
boringtun loopback handshake with a local keypair, `wg_verify_transport_completes_a_real_handshake_with_a_peer`)
(updated 2026-08-13: registration proven live — real identity via v0a884 with
wgcf-matching payload (full `tos` timestamp, `type` field, okhttp UA, retry on
blackholed DNS IPs), real wgconf generated + exported, and the scan engine
completed a real WireGuard handshake against 162.159.192.5:2408 with the
registered keypair)

## Phase 5: Geo + integration
- [x] Task 15: Geo (mmdb embed, country, colo trace)
- [x] Task 16: Engine integration (colo/loss/sort keys)

**Checkpoint F:** complete result columns + sorting

## Phase 6: Release + docs
- [x] Task 17: dist config + release pipeline
- [x] Task 18: README + ADRs + caveats
- [x] Task 19: Final review (review/simplify/security pass)

**Checkpoint G:** v0.1.0 release ready

## Phase 7: v0.2/v0.3 backlog (post-release)
- [x] Task 20: CI hardening — checkout@v6 (Node 20 deprecation), `cargo audit`
      as a CI Checks job
- [x] Task 21: Packaging — foreign 0-byte placeholder dropped from release
      archives at build time
- [x] Task 22: UI polish — dark mode, result density toggle, latency
      histogram in the summary bar
- [x] Task 23: Fragment preset editor in the UI (custom light/medium/heavy),
      round-trip through the existing API config
- [x] Task 24: Scan profiles — in-memory save/load of named configs (no
      persistence without spec sign-off)
- [x] Task 25: Results export — client-side CSV/JSON, explicit user action
- [x] Task 26: WARP wgconf import UX — paste box + file picker
- [x] Task 27: IPv6 candidate ranges in phase 1 (official CF v6 lists, opt-in
      toggle)
- [x] Task 28: `ranges refresh` background refresh + last-updated timestamp
      in the UI

**Checkpoint H:** v0.2 features complete — 4 parallel branches + PRs #1-#4,
merged 2026-08-13, 193 tests green; v0.3.0 shipped after (custom design
system, /api/status, toast system, multi-format export, profile
sanitization).

> Current state: see the [finished-product review
> (2026-08-13)](../docs/review/product-review-2026-08-13.md) and
> `CHANGELOG.md`. This ledger records shipped tasks; the review report tracks
> the open work.
