# CF-Scanner documentation index

Start with [CONTEXT.md](../CONTEXT.md), the progressive project map
(orientation, module index, invariants, glossary). Go deeper from here.

## Design and intent

- [intent/cf-scanner.md](intent/cf-scanner.md): the confirmed user intent
  with verified research corrections (the original intent record)
- [spec.md](spec.md): the approved spec (v0.4.0 baseline; deltas tracked in
  CHANGELOG, ADRs, and the review report)
- [review/product-review-2026-08-13.md](review/product-review-2026-08-13.md):
  the finished-product review (the implementation contract for the
  `review/*` branches)

## Decisions (ADRs)

Titles below match the files exactly.

- [ADR-001: Xray as subprocess with release-archive bundling](decisions/ADR-001-xray-subprocess-and-bundling.md)
- [ADR-002: boringtun for WARP UDP probes](decisions/ADR-002-boringtun-warp-probes.md)
- [ADR-003: Embedded db-ip Lite MMDB for country lookup](decisions/ADR-003-dbip-embedded-geoip.md)
- [ADR-004: DPI-bypass fragmentation via freedom outbound + sockopt.dialerProxy](decisions/ADR-004-dpi-fragment-chain.md)
- [ADR-005: Single binary, one engine, embedded UI, contract-first API](decisions/ADR-005-single-binary-contract-first.md)
- [ADR-006: No history, no telemetry — last-scan-only results in memory](decisions/ADR-006-no-history-no-telemetry.md)
- [ADR-007: Central versioning control and cargo-dist publishing pipeline](decisions/ADR-007-central-versioning-and-publishing.md)
- [ADR-008: Dist-parity release profile and explicit tokio features](decisions/ADR-008-dist-parity-release-profile-and-tokio-features.md)
- [ADR-009: Drop macOS release targets](decisions/ADR-009-drop-macos-release-targets.md)
- [ADR-010: API hardening — localhost-only, register rate limit, overwrite guard](decisions/ADR-010-api-hardening.md)
- [ADR-011: Contract boundary — shared API types are the contract](decisions/ADR-011-contract-boundary.md)
- [ADR-012: Review-scope decisions](decisions/ADR-012-review-scope-decisions.md)

## Engineering

- [development.md](development.md): local build and test flow, including the
  dist smoke test and placeholder restore
- [release-process.md](release-process.md): versioning control and the
  publishing pipeline, including release, tag, and fix flows

## Tracking

- [tasks/wayfinder-map.md](../tasks/wayfinder-map.md): the v0.8.0 ten-agent
  review remediation ledger with consolidated findings, scores, and
  decisions, including what was deliberately not done and why
- [tasks/plan.md](../tasks/plan.md): the historical implementation plan,
  superseded by todo.md and the review report
- [tasks/todo.md](../tasks/todo.md): the shipped task list
- [CHANGELOG.md](../CHANGELOG.md): the change log, newest on top

## Quality

- [ui-research-report.md](ui-research-report.md): a frontend research
  snapshot from before 0.2.0. It is annotated; "Needs change" there is not
  open work.
- [qa-runbook.md](qa-runbook.md): the manual QA runbook for live checks:
  phase 2, WARP, registration, and ranges refresh
