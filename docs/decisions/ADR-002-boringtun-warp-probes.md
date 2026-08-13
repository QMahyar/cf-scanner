# ADR-002: boringtun for WARP UDP probes

## Status
Accepted

## Date
2026-08-13

## Context
WARP mode probes Cloudflare UDP endpoints (2408/500/1709/4500) with a real
WireGuard handshake. A valid Init message with a correct MAC1 is mandatory to
elicit any reply; MAC2 may be zeros. Hand-rolling the WireGuard crypto
(noise, HKDF, X25519, MAC) would duplicate verified protocol code and invite
subtle correctness bugs. Cloudflare answers handshakes for arbitrary client
keys, so dummy-key probes work (empirical wgcf-ecosystem norm).

## Decision
Use the `boringtun` crate (Cloudflare, maintained) to build the Init message
with a valid MAC1 and to parse replies. An endpoint is open if we receive a
structurally valid Response (type 2, 92 B) or Cookie (type 3, 64 B).

The receiver index in replies does NOT match the Init's sender index for
dummy-key probes — Cloudflare answers under its own session index. Classify
on packet shape alone, never on index matching.

## Alternatives Considered

### Hand-rolled WireGuard crypto
- Pros: zero dependencies
- Cons: reimplements noise protocol, replay, key derivation; high bug risk
- Rejected: protocol security-critical and subtle

### Spawn wireguard-go / system wireguard
- Pros: battle-tested
- Cons: not cross-platform-shippable in one binary; needs root/admin on most
  platforms
- Rejected: violates single-binary constraint

### Receiver-index matching (initial design)
- Pros: strictest classification
- Cons: verified live 2026-08-13 that real WARP replies carry Cloudflare's own
  session index; matching would mark every open endpoint closed
- Rejected: shape-based classification is the wgcf-ecosystem norm

## Consequences
- The WARP server public key is bundled as a known constant and refreshed from
  the registration API when available.
- Probe classification is conservative: Response or Cookie of exact shape
  (type + length) = open; anything else = closed.
- Tests can exercise Init building and reply parsing without touching the
  network (boringtun is pure Rust).
