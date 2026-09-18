# 01: WARP/AWG obfuscation scope (junk / I1 / MASQUE / nesting)

**Type:** research (AFK)

**Blocked by:** none

**Status:** resolved

## Question

Which warpscout DPI-evasion transports should CF-Scanner adopt, in which
order, and with which crates — AmneziaWG junk (`-jc/-jmin/-jmax`,
`-gen-junk`), I1 generators (QUIC-Initial-as-I1, `quic.go`/`i1gen.go`),
MASQUE / MASQUE-H2, WARP-in-WARP nesting — and which do we explicitly
reject for a pure-CLI Rust scanner?

## Context

- warpscout audit: 4 transports (`warp.go:149-183`), default I1 = iCloud
  probe, `find-junk`/`find-sni` threshold loops print reusable commands,
  nesting via netstack-bound socket + MTU−60 (`nest.go:193-260`).
- Our baseline: boringtun Init probe, shape-only open classification,
  per-controller `SocketCache`, server pubkey resolved once per scan.
  WARP mode has no noise/obfuscation concept today.

## Answer (2026-09-18)

Crate decision up front: keep `boringtun 0.7.1` (`Cargo.toml:20`); **no new
dependency** for ranks 1-2. Junk is plain UDP datagrams around the existing
`Tunn::format_handshake_initiation` (`src/warp.rs:258-264`) via the existing
`SocketCache::get_or_bind` (`src/warp.rs:108-134`) + `rand_core 0.6.4`
(`Cargo.toml:26`). No AWG fork crate is endorsed: the registry was
unreachable from this session, so fork names/versions are fog for the
implementation ticket to confirm. Load-bearing wire fact: junk sent as
*separate* datagrams is safe against the plain-WG CF edge (server drops
unknown packets); H/S/I1 *mutations of the Init itself* require an
AWG-speaking server, so discovery must never mutate the Init while the
verify path must honor the params.

| Rank | Item | Verdict | Crate | Rationale |
|---|---|---|---|---|
| 1 | AWG junk-send (`-jc/-jmin/-jmax`, `-gen-junk` values) in discovery probe | Adopt first (S: `src/warp.rs` + `WarpConfig` fields) | none | Only DPI-noise that cannot break the plain-WG handshake; junk datagrams go through `send_bounded` (`src/warp.rs:230-236`) so the per-call timeout rule holds; loss accounting (`src/engine/warp.rs:139-180`) untouched — junk sends are not probes, `Working` stays open + zero loss per glossary |
| 2 | Honor parsed `H1-H4`/`S1-S2` + I1-generator first packet in `verify-with-wgconf` path | Adopt second (S/M: `src/warp.rs:143-191`) | none | Correctness, not just evasion: `AmneziaParams` is already parsed/rendered (`src/wgconf.rs:22-33,259-292`) but `WgVerifyTransport` ignores it (`src/warp.rs:143-160`), so verify against an AWG gateway with nonzero params fails today; QUIC-Initial-as-I1 belongs here too (AWG endpoints only) |
| 3 | QUIC-Initial-as-I1 for CF discovery | Reject | — | CF edge is plain WG and cannot answer a disguised I1; breaks the shape-only open rule (`src/warp.rs:405-411`, Response 92B / Cookie 64B to our Init) |
| 4 | `find-junk`/`find-sni` tuner pattern (threshold loops printing reusable commands) | Adopt later (S CLI, feeds 08 after 03) | none | Steal the UX pattern only: tuner subcommand emitting reusable flags to stdout; no persistence beyond existing retry-last (ADR-006 holds) |
| 5 | MASQUE / MASQUE-H2 | Reject this cycle | — (no quinn/h3) | Different scanner mode (HTTPS/QUIC handshake per endpoint), XL-sized, destroys 2048-host UDP scan throughput and replaces shape classification entirely; reopen only if UDP is fully blocked |
| 6 | WARP-in-WARP nesting | Reject | — (no netstack/tun) | Needs a live WARP session during scan, breaks injectable-transport tests-never-touch-network, complicates `SocketCache` ownership + MTU; niche benefit for an endpoint finder |

Constraint checks: params travel `WarpConfig` -> transport constructor, so
per-worker bounded channels (`src/engine/warp.rs:84-92`) and producer
backpressure (`src/engine/warp.rs:108-115`) are untouched; `select!`+cancel
races (`src/engine/warp.rs:132-159`) unchanged; no global cache, no lock
across `.await` (`src/warp.rs:109-114` drops the guard before bind/connect);
pubkey still resolved once per scan (`src/warp.rs:74-80`); new `WarpConfig`
fields need `#[serde(default)]` under `deny_unknown_fields`
(`src/api/types.rs:176-177`); pure CLI, no history/telemetry; IPv4-only
scope inherited (`src/warp.rs:201-205`, `src/engine/warp.rs:241`).
- Constraints: boringtun vs amneziawg-go embedding cost, `GOMEMLIMIT` /
  `BatchSize()=1` memory notes, per-worker channels + cancel races must be
  kept, no global socket cache, every network call gets its own timeout.
- Deliverable: ranked adopt/reject table with crate choices + order, feeding
  ticket 08. Do not write implementation code; cite file:line for both sides.
