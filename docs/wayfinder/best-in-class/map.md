# wayfinder:map — Best-in-class scanner (WARP + CDN, pure CLI)

## Destination

A ranked, buildable spec that makes CF-Scanner best-in-class against
SenPaiScanner, BPB-Warp-Scanner, warpscout, and Ptechgithub/warp:
what to steal, what to skip, and why — across engine, CLI/UX, and
shipping. Both fronts in scope (close the WARP/DPI gap AND extend the
CDN lead). The map is done when every decision ticket below is resolved
and their answers are synthesized into `spec-best-in-class.md`. No code
changes land in this effort; execution is a follow-up.

## Notes

- Mode: **planning** (decisions, not deliverables). One ticket per session,
  research tickets may run in parallel.
- Tracker: local files `docs/wayfinder/best-in-class/` (map + `tickets/`),
  same convention as `competitive-catchup/`.
- Rust work: always load the `rust-engineering` skill before writing or
  reviewing Rust. Contract changes touch `src/api/types.rs` — keep
  `deny_unknown_fields` on nested types, `#[serde(default)]` on new fields,
  `ScanConfig` stays non-strict (forward-compat root). See ADR-011.
- Domain: `CONTEXT.md` glossary is load-bearing — `Working` is binary
  (row exists = works), WARP working = open + zero probe loss. Any ticket
  proposing a third state (e.g. torn-down) must reckon with this.
- Invariants (AGENTS.md, v0.8.0): per-worker bounded channels, `select!` +
  `ProbeContext::cancelled()` races, plain-push store + lazy
  `sort_if_dirty`, broadcast cap 4096, per-controller `SocketCache` (never
  hold lock across `.await`), `ranges::HTTP_CLIENT` per-hop guard + mandatory
  call-site `.timeout(...)`.
- Boundaries: pure CLI only (ADR-013); no history/telemetry (ADR-006);
  secrets never reach logs; `.dgst` verify + 64 MiB caps on xray downloads;
  scan only official CF lists / WARP pools / explicit user input.
- Audits complete (2026-09-18, subagent deep-code reports in session):
  SenPaiScanner = Go ~22k LOC, CDN-only, TUI+desktop+Android, best DPI
  *detection* (idle-hold, WS-survival, SNI rotation, budget-split timeouts,
  phase-2 fallback ladder); BPB = Go ~1.3k LOC WARP-only wizard, full-xray
  per endpoint, adaptive pre-test + noise UX worth stealing, engine not worth
  copying; warpscout = Go ~8k LOC WARP-only, wg/awg/masque/masque-h2,
  junk/I1 generators + find-junk/find-sni tuners, torn-down detection,
  WARP-in-WARP, serial speedtest, port-gate; Ptech = shell + opaque binary,
  not a scanner codebase — steal dual-format print + bind-best UX +
  registration-dance reference only.

## Decisions so far

<!-- one line per closed ticket -->

- [01: WARP/AWG obfuscation scope](tickets/01-warp-awg-obfuscation.md): junk-send first (no new crate, S), honor H/S/I1 in wgconf-verify second; reject disguised-I1 discovery, MASQUE, nesting.
- [04: CDN probe hardening](tickets/04-cdn-probe-hardening.md): keep budget-split (03 owns), opt-in SNI rotation, socks ServerName repair, tiered phase-2 ladder, burst fallback, 3 of 4 URL hardenings; drop phase-1 WS gate, phase-2 idle-hold, typo auto-correct.
- [07: Shipping discipline](tickets/07-shipping-discipline.md): keep dist + .dgst + pinned xray-version + parity + stdout/stderr guard; drop UPX/Docker/install.sh/AUR/Go-GC knobs/VERSION self-update; explicit-only self-update sketch banked for 08.
- [02: Torn-down verdict](tickets/02-torn-detection-verdict.md): keep Working binary; torn = `fail_reason="torn_down"`, export-only + diagnostic flush, opt-in via `--warp-probes >= 4`, WARP-only behavior with shared wording.
- [03: Auto-tune UX](tickets/03-auto-tune-adaptive.md): opt-in `--adaptive-retries`, `tune` subcommand, blocked-vs-slow framing + `--network-profile`, budget-split always-on.
- [06: Export + config-bind UX](tickets/06-export-config-bind-ux.md): `--bind-best`, `--show-link` to stderr + `Reserved` passthrough, `--export-live`, four wizard strings.
- [05: Pool refresh + port-gate](tickets/05-pool-port-gate-refresh.md): CDN lists == official (no refresh); append 7 missing 8.x /24s to warp-pools.txt (8→15); opt-in `--warp-port-gate` (12-addr × 4-port, 50-port escalation) in run_warp.
- [08: Final ranking + spec](tickets/08-final-ranking-spec.md): `spec-best-in-class.md` written — P0-1…P0-8 first slice, P1 backlog, rejected list. Map complete; execution is a follow-up.

## Not yet specified

- IPv6 parity details (SenPai v6 unreachable in config flow; our v6 opt-in
  scope for any new probe path).
- Speedtest policy if torn-detection lands (serial shortlist vs current
  capped per-endpoint sample).
- MASQUE transport crate choice (usque/connect-ip-go vs alternatives) if
  ticket 01 recommends MASQUE.
- Wizard text changes (bracketed-IPv6 guidance, blocked-vs-slow framing)
  graduate after tickets 03/06 resolve.
- `find-fragment` auto-tuner shape (warpscout find-junk analogue for our
  fragment presets) graduates after tickets 01/03.

## Out of scope

- GUI / desktop / mobile / Docker (ADR-013 pure CLI; SenPai Wails/Android
  and warpscout Docker explicitly not followed).
- Scan history / dated result files / telemetry / update phone-home
  (ADR-006; warpscout GitHub-API update banner explicitly not followed).
- Committing binaries to git, obfuscated scripts, hardcoded licenses,
  checksum-less curl|bash (Ptech anti-patterns; our `.dgst` + caps stand).
- Unpinned `latest` fork downloads (BPB pattern; our pinned
  `data/xray-version.txt` stands).
- Default-on speed tests (intent ban; `--speed-test` stays opt-in).
