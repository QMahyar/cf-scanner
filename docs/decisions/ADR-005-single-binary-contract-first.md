# ADR-005: Single binary, one engine, embedded UI, contract-first API

## Status
Accepted

## Date
2026-08-13

## Context
The product has three front doors: a CLI (`serve`, `scan`, `ranges`), an
interactive wizard, and a browser UI. Without a shared core, each would
grow its own scan logic, stop conditions, and result handling — three
sources of truth for the same behavior, drifting apart.

## Decision
One in-process engine (`ScanController`) owns all scanning state and
behavior. CLI, wizard, HTTP server, and frontend are thin clients of it.
The API contract lives once in `src/api/types.rs` (`ScanConfig`, `Verdict`,
`StopCondition`, events); the server maps engine domain types → API types
and never serializes engine types directly. The frontend is one embedded
HTML file (htmx + SSE, no build step) served by the same binary on
127.0.0.1. Probe transports are injectable traits so tests never touch the
network.

## Alternatives Considered

### Separate CLI and server binaries
- Pros: smaller binaries, clearer boundaries
- Cons: two artifacts to ship/version/keep in sync; contradicts single-binary
  constraint
- Rejected

### Serialize engine types directly in the API
- Pros: less mapping code
- Cons: engine refactors silently change the public contract; no stable
  boundary for CLI/agents
- Rejected: contract first is a stated project rule

### Frontend as separate build (npm/vite)
- Pros: richer UI tooling
- Cons: build step, dependency chain, distribution complexity
- Rejected: zero-build embedded HTML keeps the one-binary promise

## Consequences
- API changes require explicit review (ask first) because every client shares
  them.
- The SSE stream, JSON CLI output, and wizard share one event source.
- The embedded UI ships in the release archives alongside xray via the same
  `include` mechanism (ADR-001).
