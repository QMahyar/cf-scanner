# wayfinder:map — Mother Session (post-audit hardening program)

## Destination

Implement every worthwhile finding from the 2026-09-05 mother-session audit
(`docs/audit/mother-session/FINDINGS.md`: 5 workflows, ~625 agents, ~4.5M
tokens) as one ordered program, highest impact first, landing as **one giant
PR** against `main`. Security audit came back clean — no action. Everything
else ships: P0 correctness bugs → P1 validation → P2 coverage → P3 docs →
P4 export/distribution → P5 architecture paydown → approved P6 capabilities.

## Notes

- Effort mode: driver-executed tickets, sequential, S/M sized (≤5 files each).
- **One branch:** `review/mother-session`, cut from latest `main`. Small
  commits per ticket; single PR at the end. No version bump, no tag, no
  publish — user-gated, ships as `[Unreleased]`.
- Rust work: `rust-engineering` skill loaded. Gates per ticket:
  `cargo test` + `cargo clippy --all-targets -- -D warnings` + `cargo fmt --check`.
- Boundaries (AGENTS.md): user input validated; `.dgst` checksums for xray;
  configs/keys out of logs; no xray/mmdb binaries in git; official ranges only.
- Ask-first gates (cleared in refine, recorded in SPEC §7): `src/api/` edits
  (F-07/F-23), `--phase2-only` removal (F-09), trial-dir fail-closed (F-11),
  range-fallback warn-vs-fail (F-13), export shape decisions (F-24),
  P6 capability pulls, any new dependency, any default-behavior change.
- SPEC: `SPEC.md` (this program's contract). PLAN: `PLAN.md` (ticket order).
  Tickets: `tickets/T-XX-*.md`.

## Decisions so far

<!-- one line per closed ticket -->

- P0 complete (T-01..T-14, committed): wgconf stripped on retry save;
  phase-2 colo race closed; post-stop errors counted; neighbor drain
  double-checked; Release ordering on stop counters; retry load validates;
  serde-compat retry format (tolerant top level); saturate-then-cap (F-08
  verified not-a-bug, clarified); --phase2-only removed; precise SSRF
  literal check; trial dirs fail closed; speed-cancel cleanup; loud
  range-fallback warnings; refresh persists off async workers.
