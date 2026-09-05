# PLAN — Mother Session ticket order (impact first)

Each ticket: verify-then-fix + regression test + gates
(`cargo test`, `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check`).
Tickets T-01…T-14 are P0 (one per finding, in FINDINGS order). Later tickets
group P1→P6. P6 items enter only if pulled in refine.

| # | Ticket | Finding | Impact |
|---|--------|---------|--------|
| T-01 | strip-wgconf-on-save | F-01 | promise/security |
| T-02 | phase2-colo-race | F-02 | data loss race |
| T-03 | phase2-error-counters | F-03 | wrong stats |
| T-04 | neighbor-drain-race | F-04 | data loss race |
| T-05 | atomic-ordering-release | F-05 | ARM correctness |
| T-06 | retry-load-validates | F-06 | invalid config → engine |
| T-07 | serde-compat-retry | F-07 | compat (ask-first) |
| T-08 | wizard-truncation-clamp | F-08 | wrong cap |
| T-09 | phase2-only-flag | F-09 | dead flag (ask-first) |
| T-10 | ssrf-hex-false-positive | F-10 | over-blocking |
| T-11 | trial-dir-fail-closed | F-11 | creds + errors (ask-first) |
| T-12 | speed-cancel-cleanup | F-12 | resource leak |
| T-13 | range-fallback-signals | F-13 | silent fallback (ask-first) |
| T-14 | refresh-spawn-blocking | F-14 | runtime blocking |
| T-15 | validation-rejections | F-15 | API gaps |
| T-16 | validation-serde-tests | F-16 | test gaps |
| T-17 | critical-path-coverage | F-17 | xray/verify/socks/http tests |
| T-18 | unit-edge-coverage | F-18 | per-module edges |
| T-19 | cli-e2e-gaps | F-19 | E2E formats/modes |
| T-20 | cli-reference-docs | F-20 | README + help text + CI gate |
| T-21 | changelog-hygiene | F-21 | [Unreleased] + ordering |
| T-22 | doc-drift-sweep | F-22 | ADRs/intent/AGENTS/meta |
| T-23 | dead-type-removal | F-23 | dead code (ask-first) |
| T-24 | export-additive | F-24 | formats + fixes (ask-first on shape) |
| T-25 | npm-hardening | F-25 | wrapper guards + docs |
| T-26 | release-hardening | F-26 | MSI/gates/locked/matrix |
| T-27 | arch-paydown-1 (configs split) | F-27.1 | structure |
| T-28 | arch-paydown-2 (validate split) | F-27.2 | structure |
| T-29 | arch-paydown-3 (loop driver) | F-27.3 | dedupe |
| T-30 | arch-paydown-4 (controller groups) | F-27.4 | god object |
| T-31 | arch-paydown-5 (tunnel/error recon) | F-27.5 | overlap |
| T-32 | arch-paydown-6 (export registry) | F-27.6 | extensibility |
| T-33 | arch-paydown-7 (perf micros) | F-27.7 | hot path |
| T-34+ | P6 pulls (only if approved) | C-1…C-6 | capabilities |
| FINAL | giant PR: rebase, full gates, CHANGELOG, `gh pr create` | — | — |

Parallelization: none — sequential on one branch (wayfinder convention:
plain branches, no worktrees; here a single branch since one PR).
