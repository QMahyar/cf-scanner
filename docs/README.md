# CF-Scanner — Documentation Index

Start with [CONTEXT.md](../CONTEXT.md) for the progressive project map
(orientation → module index → invariants → glossary), then go deeper here.

## Design & intent

- [intent/cf-scanner.md](intent/cf-scanner.md) — confirmed user intent +
  verified research corrections (original intent record)
- [spec.md](spec.md) — the approved spec (v0.4.0 baseline; deltas tracked in
  CHANGELOG/ADRs/review report)
- [review/product-review-2026-08-13.md](review/product-review-2026-08-13.md) —
  finished-product review (implementation contract for the `review/*` branches)

## Decisions (ADRs)

- [ADR-001 — xray subprocess and bundling](decisions/ADR-001-xray-subprocess-and-bundling.md)
- [ADR-002 — boringtun WARP probes](decisions/ADR-002-boringtun-warp-probes.md)
- [ADR-003 — db-ip embedded GeoIP](decisions/ADR-003-dbip-embedded-geoip.md)
- [ADR-004 — DPI fragment chain](decisions/ADR-004-dpi-fragment-chain.md)
- [ADR-005 — single binary, contract first](decisions/ADR-005-single-binary-contract-first.md)
- [ADR-006 — no history, no telemetry](decisions/ADR-006-no-history-no-telemetry.md)
- [ADR-007 — central versioning and publishing](decisions/ADR-007-central-versioning-and-publishing.md)
- [ADR-008 — dist parity, release profile, tokio features](decisions/ADR-008-dist-parity-release-profile-and-tokio-features.md)
- [ADR-009 — drop macOS release targets](decisions/ADR-009-drop-macos-release-targets.md)
- [ADR-010 — API hardening](decisions/ADR-010-api-hardening.md)
- [ADR-011 — contract boundary](decisions/ADR-011-contract-boundary.md)

## Engineering

- [development.md](development.md) — local build + test flow (incl. dist
  smoke test + placeholder restore)
- [release-process.md](release-process.md) — versioning control + publishing
  pipeline (release/tag/fix flows)

## Tracking

- [tasks/wayfinder-map.md](../tasks/wayfinder-map.md) — v0.8.0 ten-agent
  review remediation: consolidated/deduplicated findings, scores, decisions
  (incl. what was deliberately NOT done and why)
- [tasks/plan.md](../tasks/plan.md) — implementation plan (historical ledger;
  superseded by todo.md + the review report)
- [tasks/todo.md](../tasks/todo.md) — shipped task list
- [CHANGELOG.md](../CHANGELOG.md) — change log (newest on top)

## Quality

- [ui-research-report.md](ui-research-report.md) — frontend research snapshot
  (pre-0.2.0; annotated — "Needs change" is not open work)
- [qa-runbook.md](qa-runbook.md) — manual QA runbook for live verification
  (phase-2 / WARP / registration / ranges refresh)