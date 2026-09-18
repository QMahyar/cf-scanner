# 09: warp-config export --bind-best + Reserved passthrough

**What to build:** the generated WireGuard config can leave with the scan's best endpoint already stamped in — non-interactively — and imports cleanly into V2rayNG-style clients: `--bind-best` fills Endpoint from the lowest-latency last-scan result (explicit `--endpoint` wins, empty results error), and the AmneziaWG Reserved field round-trips through parse and render (default off).

**Blocked by:** None (can start immediately).

**Status:** done

## Result (driver close-out 2026-09-18)

Implemented by subagent (session lost to an API-key error before close-out;
driver verified and closed): `warp-config export --bind-best [--out FILE]`
+ additive `Reserved` parse/render passthrough. Pure planner
(`plan_warp_export_endpoint`, `src/main.rs`): explicit `--endpoint` wins,
lowest-latency working result stamped otherwise (bracketed IPv6), hard error
when empty; stdout keeps exactly the conf body, note on stderr. Note: in a
fresh process the in-memory last scan is empty by construction (no-history
invariant), so bare `--bind-best` fails fast with the explicit-endpoint hint
— planner is ready for any future in-process caller. Reserved round-trips,
default-off, strict rejects intact.

- [x] `--bind-best [--out FILE]` on warp-config export; file/`-` body shape unchanged; human note on stderr; stdout keeps exactly one artifact
- [x] Additive Reserved parse/render passthrough with round-trip tests (parser rejects stay strict; no behavior change when absent)
- [x] Wizard's existing interactive behavior unchanged
- [x] `cargo test` + `cargo clippy --all-targets -- -D warnings` + `cargo fmt --check` green

Gate evidence (driver-run, full tree): `cargo test` 0 failed, clippy
`-D warnings` clean, `cargo fmt --check` clean after driver applied `cargo
fmt` (4 hunks in `wgconf.rs`/`cli.rs` only). Reviewed: planner + tests +
flag wiring; `scan_args.rs` hunks in tree belong to 07/08, untouched here.

Spec: `../spec-best-in-class.md` §P0-8. Inherits spec §6 execution rules.

- [ ] `--bind-best [--out FILE]` on warp-config export; file/`-` body shape unchanged; human note on stderr; stdout keeps exactly one artifact
- [ ] Additive Reserved parse/render passthrough with round-trip tests (parser rejects stay strict; no behavior change when absent)
- [ ] Wizard's existing interactive behavior unchanged
- [ ] `cargo test` + `cargo clippy --all-targets -- -D warnings` + `cargo fmt --check` green
