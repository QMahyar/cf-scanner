# ADR-011: Contract boundary — shared API types are the contract

## Status
Accepted. Amends ADR-005 (its status line points here).

## Date
2026-08-16

## Context
ADR-005 decided "contract first": the API contract lives once in
`src/api/types.rs` (`ScanConfig`, `Verdict`, `StopCondition`, events), the
server maps engine domain types → API types, and engine types are never
serialized directly. The finished-product review (2026-08-13) re-examined
this boundary: engine modules return domain-shaped types (probe verdicts,
plan items) that are close to — but not identical to — the API types. A
tempting cleanup is a dedicated domain layer (`domain/` types + a mapping
module) so the engine never touches API vocabulary. That would duplicate
the contract and add mapping surface without changing what any client
observes.

## Decision
The shared `src/api/types.rs` remains THE API contract — no domain-layer
refactor. The engine returns domain types (its natural internal shapes),
the server owns the domain → API mapping at the boundary, and engine types
are never serialized directly. This amends ADR-005 only in that the "domain
types" are explicitly the engine's internal shapes, not a second vocabulary
to build and maintain.

## Alternatives Considered

### Dedicated domain layer with its own type system
- Pros: engine fully decoupled from API vocabulary
- Cons: two type systems to keep in sync for zero client-visible benefit;
  mapping bugs become a new failure mode; the engine already returns domain
  shapes the server maps at the edge
- Rejected

### Serialize engine types directly (relax the boundary)
- Pros: less mapping code
- Cons: engine refactors silently change the public contract; no stable
  boundary for CLI/agents — already rejected in ADR-005
- Rejected

## Consequences
- The boundary rule is explicit: `src/api/types.rs` is the contract; engine
  types never serialize directly; the server owns the domain → API mapping.
- Refactors inside the engine cannot leak into the API; API contract changes
  stay "ask first" (AGENTS.md).
- ADR-005's status now points here, so the trail reads as one continuous
  decision rather than two competing ones.

## Links
- ADR-005 — single binary, contract first