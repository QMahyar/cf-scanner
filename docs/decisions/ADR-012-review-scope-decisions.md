# ADR-012: Review-remediation scope decisions

## Status

Accepted (2026-08-25)

## Context

The 2026-08-24 ten-agent review produced findings that overlap earlier
architectural decisions. Three kept resurfacing as "gaps" even though each
was already ruled on. This ADR records the final calls so they stop
reappearing on remediation lists.

## Decisions

### 1. Engine consumes `api::types` directly — no domain-type split

ADR-011 made the shared API types THE contract; adding a parallel engine
domain layer plus `From` mappings would duplicate every type for zero wire
safety (nothing engine-side is ever serialized). Re-confirmed.

Consequence: new request fields land once, in `src/api/types.rs`, with
`#[serde(default)]`.

### 2. No `#[serde(other)]` fallback variants on Mode/Preset enums

A silent fallback (`unknown preset -> Quick`) would run a different scan
than the caller asked for, and the failure mode is invisible. serde's
existing "unknown variant" rejection is louder and strictly more useful,
especially with `deny_unknown_fields` (v0.8.0) catching typos at the same
layer. Rejected permanently.

### 3. SBOM yes (cargo-sbom), cosign no

XTLS publishes `.dgst` checksums but no signatures, so cosign verification
of the bundled xray is impossible today; the checksum plus GitHub artifact
attestations remain the integrity story (documented in README Security).
What we CAN ship is an SBOM of our own binary: release builds emit an
SPDX JSON via cargo-sbom and attach it to the GitHub Release.

## Consequences

- `release.yml` gains an `sbom` step in `build-global-artifacts`.
- Any future "add a domain Verdict" or "tolerate unknown enum values"
  proposal must overturn this ADR first.
