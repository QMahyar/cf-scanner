# 05: WARP DPI-noise core (junk-send discovery + H/S/I1 verify)

**What to build:** WARP scans survive DPI-filtered networks two ways: (a) the discovery probe can send junk padding datagrams around the handshake (off by default; loss accounting untouched — junk sends are not probes, Working stays open + zero loss); (b) verification with the user's own config honors its AmneziaWG H/S/I1 parameters, so verifying against an AWG gateway with nonzero params stops failing.

**Blocked by:** None (can start immediately).

**Status:** done

Spec: `../spec-best-in-class.md` §P0-5. Inherits spec §6 execution rules.

- [x] New WarpConfig fields (off/zero defaults) with `#[serde(default)]` under `deny_unknown_fields`; discovery never mutates the handshake Init itself (plain-WG edge safety)
- [x] Junk sends obey the per-call timeout rule; per-worker channels, backpressure, and cancel races untouched; pubkey still resolved once per scan
- [x] Verify path honors parsed H/S/I1 (round-trip test: nonzero-param config verifies where it previously failed)
- [x] Mock-transport tests: junk datagrams emitted around (never inside) the Init; loss/Working semantics unchanged
- [x] `cargo test` + `cargo clippy --all-targets -- -D warnings` + `cargo fmt --check` green (clippy: see out-of-scope note)

## Result

**Flag names (new, all `--mode warp`-only, `WARP` help heading):**
- `--warp-junk-count N` → `WarpConfig.junk_count: u8` (0 = off default, max 128)
- `--warp-junk-min BYTES` → `WarpConfig.junk_min: u16` (default 0)
- `--warp-junk-max BYTES` → `WarpConfig.junk_max: u16` (default 0, max 1280)
- CDN mode rejects all three by explicit flag name (even `Some(0)` never silently no-ops, mirroring `--warp-probes`).

**Files changed (mine):** `src/warp.rs` (JunkConfig, H/S translates, 7 new tests),
`src/api/types.rs` (3 WarpConfig fields + validate), `src/api/limits.rs`
(`MAX_WARP_JUNK_COUNT/_SIZE`), `src/api/error.rs` (`InvalidJunkCount/_Size`),
`src/cli.rs` (flags), `src/cli/scan_args.rs` (mapping + CDN gating),
`src/cli/scan_args/tests.rs` (5 new tests), `src/cli_wizard.rs` (2-line
`..Default::default()` compile fix only), `src/api/types_tests.rs` (round-trip
fixture extended with junk values), `README.md` (3 flag rows — required by the
`every_long_scan_flag_is_documented_in_help_and_readme` gate).
`rust-engineering` skill unavailable; proceeded per spec §6 + AGENTS.md with
`rust-async` loaded. No new dependencies (`rand_core 0.6.4` + `SocketCache` reused).

**Behavior:**
- Discovery: `count/2` junk datagrams before the Init, remainder after, via
  `send_bounded` (per-call timeout holds); sizes uniform in `[min, max]`
  (clamped ≥1 byte). Init bytes untouched; junk never counted
  (`ProbeOutcome::plain` stays sent=1/received=1, engine loss rule untouched).
- Verify (`WgVerifyTransport`, works end-to-end today — engine already passes
  `&wg`): H1–H4 magic swap + S1 append on the first packet, H2/S2 strip on the
  response, H4 swap on data/keepalive both ways; identity params
  (None, or H=1..4/S=0 as in `tests/fixtures/warp-wgconf.txt`) take the
  byte-identical vanilla path. QUIC-disguised-I1 NOT included (no test oracle;
  R1 rejects it for discovery; verify-side disguise is a follow-up).
- Known wiring gap (engine-owned, deliberately not touched): `run_warp`
  (`src/engine/warp.rs`, parallel ticket in flight) still builds
  `WarpTransport::with_cache` (junk off). Discovery junk is transport-ready via
  new `with_junk` / `with_cache_and_junk` constructors; the call-site change is
  a ~3-line follow-up once the engine file is free.

**Gate evidence:** `cargo test` all green (697 lib incl. 7 new warp + 5 new CLI
tests, 61 bin, 16 + 16 + 2 integration, 0 failed). `cargo fmt --check` clean.
`cargo clippy --all-targets -- -D warnings` fails ONLY on
`src/engine/speed.rs:181` (`manual_clamp`, parallel ticket 14's in-flight
burst code — verified via `git diff`, never opened by this ticket, left
untouched per scope); warnings-mode clippy shows zero lints in this ticket's files.
