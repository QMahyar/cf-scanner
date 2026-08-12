# CF-Scanner — Task List

Status legend: [ ] todo · [~] in progress · [x] done

## Phase 0: Foundation
- [x] Task 1: Project skeleton (Cargo.toml, layout, .gitignore, PR CI)
- [x] Task 2: API contract types + validation

**Checkpoint A:** build clean, tests green, human review of plan

## Phase 1: Engine core
- [x] Task 3: Ranges (bundled CF, presets, exclusions, custom CIDR)
- [x] Task 4: TLS probe (tokio-rustls, latency, injectable)
- [ ] Task 5: ScanController (stop conditions, pool, events, results store)
- [ ] Task 6: Server API (axum, SSE, static embed)

**Checkpoint B:** phase-1 end-to-end via API

## Phase 2: Frontend + CLI
- [ ] Task 7: Frontend embed (htmx + SSE + Pico, sortable table)
- [ ] Task 8: CLI (serve/scan/ranges, JSON lines, wizard)

**Checkpoint C:** full UX loop in browser + CLI

## Phase 3: CDN phase 2
- [ ] Task 9: Config parsers (URIs, subscriptions, Xray JSON)
- [ ] Task 10: Xray manager (bundle, checksum, spawn, fragment builder)
- [ ] Task 11: Phase-2 verifier (tunnel HTTP check, verdict)

**Checkpoint D:** phase-2 verdicts with real xray

## Phase 4: WARP
- [ ] Task 12: WARP probe (pools, ports, boringtun, loss)
- [ ] Task 13: wgconf parse + real-config verification
- [ ] Task 14: WARP registration (v0a884, wgconf builder, WARP+, export)

**Checkpoint E:** WARP end-to-end

## Phase 5: Geo + integration
- [ ] Task 15: Geo (mmdb embed, country, colo trace)
- [ ] Task 16: Engine integration (colo/loss/sort keys)

**Checkpoint F:** complete result columns + sorting

## Phase 6: Release + docs
- [ ] Task 17: dist config + release pipeline
- [ ] Task 18: README + ADRs + caveats
- [ ] Task 19: Final review (review/simplify/security pass)

**Checkpoint G:** v0.1.0 release ready
