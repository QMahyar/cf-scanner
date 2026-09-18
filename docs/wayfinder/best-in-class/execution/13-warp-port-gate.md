# 13: Opt-in WARP port gate (fail-fast narrowing)

**What to build:** WARP scans on dead ports stop slowly probing every endpoint: an opt-in gate first handshakes a 12-address sample across the primary ports (escalating to the extended list only on total failure), narrows the scan to what answered, and aborts with a human note — never an error — when nothing is reachable. Explicit `--ports`/`--warp-endpoints` skip the gate.

**Blocked by:** 01 (pool totals and size-derived expectations must be final first).

**Status:** done

## Result (driver-implemented 2026-09-18; subagents unavailable — invalid API key)

Opt-in `--warp-port-gate`: 12 sampled pool endpoints × primary
`[2408,500,1701,4500]`, escalating to the 50-port extended list (BPB's full
54 minus primaries, count-pinned by test) on total failure. Open ports narrow
the scan (via `cfg.ports`, so preflight/groups/counting follow automatically);
total failure aborts with an empty summary + stderr note, never an error.
Skipped with a note on explicit ports/endpoints or wgconf verify; empty
sample keeps configured ports.

- [x] `PRIMARY_WARP_PORTS`/`EXTENDED_WARP_PORTS`/`PORT_GATE_SAMPLE` consts in
      `warp.rs` (provenance comments; 4+50 disjointness pinned by test)
- [x] `WarpConfig.port_gate` (serde default, off) + `--warp-port-gate` flag +
      WARP-mode gate + README row; `gate_applies` skip predicate
- [x] Shared `sample_pool_hosts` extractor (preflight refactored onto it,
      byte-identical streams — its pinned tests still pass); cancel-safe
      JoinSet fan-out; per-call timeouts; no verdicts recorded by the gate
- [x] 8 new tests incl. the strong narrowing proof (deterministic samples
      scripted offline: `scanned == groups.len()`, all results port 2408)
      and the total-failure abort e2e; none deleted
- [x] `cargo test` (739 lib + all targets, 0 failed) + `cargo clippy
      --all-targets -- -D warnings` + `cargo fmt --check` green

Note: 05's junk-wiring gap and 06's torn-wording follow-up (both in these
files' neighborhood) were completed by the driver beforehand — 13 stayed
pure port-gate.

Spec: `../spec-best-in-class.md` §P1-4. Inherits spec §6 execution rules.

- [ ] `--warp-port-gate` flag (new WarpConfig flag with default, `deny_unknown_fields` kept); gate runs between transport build and scan fan-out reusing the built transport (cache ownership, cancel races, timeouts preserved)
- [ ] Skip conditions mirror the spec (explicit ports/endpoints); total failure returns an empty summary + stderr note
- [ ] Tests with injected transports (open → narrowed set, total-failure → empty summary, skip conditions); defaults unchanged when flag absent
- [ ] `cargo test` + `cargo clippy --all-targets -- -D warnings` + `cargo fmt --check` green
