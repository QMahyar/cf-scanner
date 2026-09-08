# Mother Session — Complete Findings Catalog

Date: 2026-09-05. Program: 5 deep workflows, ~625 agents, ~4.5M tokens.
Base: v0.13.0 (`cf-scanner` 0.13.0, pure CLI, ~23K LOC Rust).

Evidence: raw agent outputs in this directory
(`wf_*.extract.json`, extracted from the workflow journals).
Each finding below cites its source workflow:
**BUG** (code bug hunt), **SEC** (security audit), **ARCH** (architecture),
**TEST** (testing & reliability), **DOC** (docs & production).

## Verdicts up front (read first)

- **Code correctness: GOOD.** BUG produced 132 raw findings; adversarial
  verification confirmed 0 (verify agents mostly timed out, so the 27
  "major" raw findings below are TRIAGED BY A HUMAN, not machine-confirmed —
  each ticket says "verify then fix").
- **Security: CLEAN.** SEC mapped 5 attack surfaces; deep-audit agents found
  0 exploitable vulnerabilities. The ADR-013 server removal eliminated the
  remotely-reachable surface. Nothing to fix; the audit itself is the artifact.
- **Everything else: REAL WORK.** 179 ARCH + 75 TEST + 75 DOC findings.
  Triaged by impact below, P0 first.

## P0 — Correctness & security-behavior bugs (fix first, in this order)

### F-01 `save_config` persists `warp.wgconf` against its own promise (SEC-adjacent)
- Source: BUG-49. File: `src/retry.rs:16-23`.
- `--retry-last` help (`src/cli.rs:308-312`) promises "Phase-2 configs and
  WARP keys are never saved", but `save_config` only drops `phase2` —
  `warp.wgconf` (WireGuard **private key**) is serialized to `last-scan.json`.
- Mitigating: the file goes through `write_secret` (0600 Unix). Still a
  promise violation: fix = strip `warp.wgconf` (and `verify_with_wgconf`?)
  on save; keep help text. Verify-then-fix.

### F-02 Concurrent colo rejection can delete a GOOD verdict (race, data loss)
- Source: BUG-111. File: `src/engine/phase2.rs:248-260`.
- Two workers on the same IP: A passes with a kept colo and stores the
  verdict; B passes with a rejected colo and calls `remove_verdict` — if B
  wins the lock race, the good verdict is deleted.
- Fix: removal must be conditional (only remove if the stored verdict is the
  rejected one — compare colo/generation, or never delete a stored passing
  verdict for a rejected-colo latecomer). Verify-then-fix with a regression test.

### F-03 Phase-2 error counters undercount once `stop_found` is met (wrong stats)
- Source: BUG-112. File: `src/engine/phase2.rs:213-216`.
- In the `Err` branch, `break` happens BEFORE `errored` increment and
  `first_error` recording when `passed.len() >= stop_found`. Summary
  undercounts errors; `done == total` terminal check can misbehave.
- Fix: record error first, then break. Verify-then-fix with test.

### F-04 Neighbor drain drops tasks on the `inflight==0` race (data loss)
- Source: BUG-35. File: `src/engine/cdn.rs:218-230`.
- Final `side_rx` drain breaks when `inflight==0`; a worker can enqueue a
  neighbor task between the decrement and the check — orphaned tasks are never
  probed or counted. Verify-then-fix (drain-then-check / generation counter).

### F-05 Atomic ordering: `Relaxed` writes, `Acquire` reads on stop counters
- Source: BUG-33/34. File: `src/engine/cdn.rs:326,328`.
- `scanned`/`found` use `fetch_add(Relaxed)` but `should_stop()` reads with
  `Acquire`. On AArch64 the producer can read stale values and overshoot
  cap/found. Fix: `Release` on the write side (free on x86, one barrier on
  ARM). Also check warp.rs for the same pattern.

### F-06 `load_config` never validates the persisted config
- Source: BUG-126. File: `src/retry.rs:30-35`.
- A hand-edited/corrupt `last-scan.json` can deserialize yet be semantically
  invalid (concurrency=0, timeout=5, mode/config mismatch) and goes straight
  to `ScanController`. Fix: call `cfg.validate()` after deserialization,
  surface a clear "saved scan invalid, re-run" error. Test with corrupt file.

### F-07 Serde forward/backward compat holes around the persisted format
- Source: BUG-30/127/128. File: `src/api/types.rs:167-187`.
- `WarpConfig.verify_with_wgconf: bool` lacks `#[serde(default)]` while the
  struct is `deny_unknown_fields` — violates the v0.8.0 invariant ("any NEW
  request field needs `#[serde(default)]`") and breaks old-JSON reads.
- Same latent issue on `ScanConfig` core fields (mode/target/ports/stop/…).
- `deny_unknown_fields` on the **persisted** retry format makes any future
  rename/removal a hard break of `--retry-last`.
- Fix (ASK-FIRST: touches `src/api/`): add `#[serde(default)]` to all
  bool/numeric/Vec/Option-compatible fields; decide retry-format policy
  (recommended: keep `deny_unknown_fields` for CLI-parsed input, but make
  `load_config` tolerant — strip unknown fields or a versioned wrapper).
  Ticket proposes; user confirms.

### F-08 Wizard `u128 → u32` truncation falls back to the wrong value
- Source: BUG-14. File: `src/cli_wizard.rs:23`.
- `u32::try_from(host_count).unwrap_or(MAX_SCAN_COUNT)` substitutes exactly
  100,000 for huge pools instead of clamping. Fix: `.unwrap_or(u32::MAX).min(MAX_SCAN_COUNT)` (or saturating cast).

### F-09 `--phase2-only` is exposed but unconditionally rejected (dead flag)
- Source: BUG-48. Files: `src/cli.rs:224`, `src/cli/scan_args.rs:195-198`,
  `src/engine/cdn.rs:115-121`.
- The flag exists in `--help`, the engine handles it, but the CLI always
  errors. ASK-FIRST: (a) remove the flag + engine dead path, or (b) wire it
  properly (needs phase-1 results source — out of scope for one-shot CLI).
  Recommendation: remove until a real design exists.

### F-10 Hex-domain SSRF check false-positives on legit hostnames
- Source: BUG-105. File: `src/ranges/http.rs:53-69`.
- The char-class test blocks real domains that look hex-like with a digit
  (`d0ad.beef`, `cafe0.bad`). Fix: only apply the hex-literal test to the
  host portion when it parses as an IP literal shape (all-numeric/hex dotted
  or `0x` prefixed), not to every hostname containing a digit. Regression test
  with `d0ad.beef`-style hosts.

### F-11 `fresh_trial_dir` swallows `create_dir_all` + `chmod` failures
- Source: BUG-42/43. File: `src/verify.rs:303-308`.
- Returns a path to a possibly-nonexistent dir (confusing downstream errors);
  silently keeps credential-bearing dirs world-readable if chmod fails.
- Fix: return `Result<PathBuf>`; propagate with context; fail closed when the
  0700 hardening cannot be applied (or warn loudly + continue — ASK as part
  of F-11 ticket; recommendation: fail closed, credentials at stake).

### F-12 `OpenedTunnel` cleanup on cancel relies on implicit `Drop`
- Source: BUG-121. Files: `src/engine/speed.rs:183-198`, `src/verify.rs:128-136`.
- If the cancel branch wins the `select!` mid-download, cleanup depends on a
  boxed future in a dropped struct with no `Drop` impl — xray child / trial
  dir may leak on cancel. Fix: explicit guard (`Drop` impl or scopeguard-style
  cleanup future awaited on cancel). Regression test with FakeOpener + cancel.

### F-13 Range pool silently falls back on refresh errors (undiagnosable)
- Source: BUG-59/60/61/62. File: `src/ranges/pool.rs:161-207`.
- `base_pool`/`base_pool_v6` discard parse errors via `.ok()`; `effective_pool`
  swallows I/O + path errors via `.ok()` / `Err(_) => None`. Corrupt refresh
  file = silent bundled fallback, no signal. (Related open item from the 2026
  review: "corrupt refreshed-ranges fails the scan" — engine/server disagreed;
  now the failure is silent instead of loud. Neither is right.)
- Fix: propagate a typed error with context; CLI warns loudly (`tracing::warn`
  + stderr note) and continues on bundled, or fails with `--strict-ranges`?
  Recommendation: warn + continue (availability), with the exact parse error
  in the message. Ticket decides; keep behavior change visible.

### F-14 `refresh_to_disk` blocks the runtime + holds std Mutex in async fn
- Source: BUG-77/78. File: `src/ranges/official.rs:18-40`, `src/ranges/pool.rs:310-327`.
- `write_pool_to` does blocking `create_dir_all`/`write`/`rename` under a
  `std::sync::Mutex` inside an async fn. Fix: `spawn_blocking` around the
  write (or async fs + `tokio::sync::Mutex`). Note TEST-30 also flags
  `fetch_*` paths untested — cover with tests using temp dirs.

## P1 — Validation gaps (API-level, no behavior change for valid input)

### F-15 Missing mode/cross-field rejections in `validate()`
- Source: ARCH-107/109/110/111/112. File: `src/api/validate.rs`,
  `src/api/limits.rs`.
- `neighbor_count` accepted in WARP mode (no-op); `probe_mode=Tcp` +
  `accepted_http_codes` accepted (codes meaningless); `stop.cap < stop.found`
  silently accepted; `validate_ports` allows 4096 raw entries pre-dedup;
  `probe_url`/`probe_urls` legacy dual-field coexistence; CLI↔API duplicate
  validation drift (ARCH-111/119).
- Fix: add the three rejections + cap-vs-found check; document pre-dedup cap;
  single-source shared predicates where cheap. Tests for each.

### F-16 Validation + serde tests missing for real rules
- Source: TEST-38/39/40/41/42. File: `src/api/types_tests.rs`.
- 10 rules with zero coverage (Phase2OnlyNeedsConfigs, Phase2OnlyWrongMode,
  WarpPresetNotAllowed, WarpCidrsNotAllowed, InvalidPhase2Concurrency,
  ConfigEntryTooLong, SniTooLong, WgconfTooLong, TooManyEndpoints, …);
  boundary values never accepted-tested (concurrency 1/1000, timeout
  100/30000, probes 1/10, HTTP codes 100/599); no round-trips for
  `Phase2Progress`/`Failed` events, full `Verdict`, `WarpConfig`, full
  `Phase2Config`.
- Fix: one test module addition, table-driven. Pure test ticket.

## P2 — Critical-path coverage (highest-risk untested code)

### F-17 Zero-coverage critical paths
- Source: TEST-1/2/4/30.
- `src/xray.rs`: `spawn`, `XrayProcess::stop`, `write_trial_config`,
  `capture_stderr`, `download_binary`, `RealFetch::bytes`, `find_entry` error
  path, `make_executable` — CRITICAL.
- `src/verify.rs`: `XrayTunnelProbe::probe`, `open_tunnel_session`,
  `RealTunnelOpener::open`, stale-dir sweep CAS, `require_xray_binary`,
  `TunnelSession::cleanup` — CRITICAL (always mocked today).
- `src/socks.rs`: `timed_download_via_socks`, `count_download`, HTTPS branch,
  `socks5_connect` addr types + error paths — HIGH.
- `src/ranges/http.rs`: `fetch_tls_with_headers`, `fetch_bytes`,
  `fetch_tls_inner`, `sanitize_url_for_error`, redirect policy — MEDIUM.
- Fix: offline harness — fake xray binary via temp dir + `CF_SCANNER_DATA_DIR`
  (pattern already proven in `tests/xray_lifecycle.rs`); loopback SOCKS5
  scripted server; `#[ignore]` live tests stay manual. No network in CI.

### F-18 Mock + edge gaps (unit level)
- Source: TEST-5..13/27/28/29/33/34/50/51/52.
- `FakeTransport` never emits `ProbeError::{Timeout,TlsHandshake,…}` in CDN
  tests; `FakeOpener::open` never `Err`s; `enrich::{lookup,enrich_working}`
  untested (needs injected HTTP — add seam); `util::percent_decode` zero
  coverage; `geo::parse_colo` CRLF/multi-line/4-char/private-range edges;
  `wgconf` render edges (empty AllowedIPs, MTU boundary, `mtu=abc`, wg://
  round-trip); `dgst::hex_lower` + multi-line edge; `paths::write_secret`
  Unix-0600 path + poison-guard path; `export::write_export` orchestrator;
  `probe::parse_status_line` HTTP/2, accepted-code filtering, `remark_for`
  phase2-no-colo, `unique_tag` dedup suffix, `plan_probe_count`;
  `pool`: `/0` host_count boundary, overlapping exclusions, `parse_lines`
  `#` comments, `write_pool_to` tmp naming; `official`: malformed JSON/text
  refresh, empty arrays, whitespace-only, refresh races, atomicity;
  `retry`: corrupt JSON, concurrent save/load, read-only dir, pathological
  size; `store`: remove-missing, empty merge, colo update, ISP truncation;
  `speed`: cancel mid-download, opener-fail, NaN min-speed, empty candidates;
  `neighbor`: channel-full; `phase2`: unknown verifier tag, http:// prefix,
  sub-spec caps; engine: WARP worker panic, mixed OK/Err sequences.
- Fix: table-driven unit tests per module; one ticket per area (S/M sized).

### F-19 CLI end-to-end gaps
- Source: TEST-24/32. File: `tests/cli_scan_agent.rs`.
- Missing: `--export-format base64|raw|singbox|clash` file checks,
  `--json-errors`, `--wizard` smoke, WARP mode via CLI, phase-2 via CLI
  (offline fakes). Extend the existing E2E harness.

## P3 — Docs & developer experience

### F-20 CLI reference incomplete (README + `--help`)
- Source: DOC-1..7/30..39, ARCH-123/125/126/127/128/130.
- README Commands table omits `--phase2-*` (6 flags), `--warp-*` (4),
  `--concurrency/--timeout-ms/--exclude/--custom-cidrs/--seed/--http-status-code`,
  `export-config --sni`, `warp-config` sub-flags, `--ipv6` on scan.
- 15 flags have ZERO help text (`--json-errors` included); `--min-latency`
  text misleads; `--target` vs `--cap` semantics undocumented; preset
  sizes (quick/normal/full) undescribed; `--phase2-fragment` values lack
  byte/timing details; `--enrich-asn` under wrong heading; `--neighbor-scan`
  jargon; EXAMPLES constant has conflicting flags; `export-config` vague.
- Zero WARP/phase-2 troubleshooting; missing key-workflow examples.
- Fix: rewrite Commands reference (single source: generate from `--help`? at
  minimum hand-sync + a CI grep gate for "flags without help text");
  add Troubleshooting (WARP/phase-2/ranges/xray-glibc); fix all help strings
  in `src/cli.rs`. No `--quiet/--no-progress` addition in this round
  (ARCH-130 noted; defer — new flag = scope creep; stderr is already
  TTY-gated).

### F-21 CHANGELOG hygiene
- Source: DOC-14/15/16. Missing `[Unreleased]`; 0.12.x/0.11.x ordering
  broken; non-standard subsections. Fix + add `[Unreleased]` with this
  program's entries.

### F-22 Doc drift fixes (small, mechanical)
- Source: DOC-8..12/40..42/57/61/62/63/71/72, ARCH-1..8/12/19/77/78.
- `docs/development.md`: MSRV 1.85 → 1.88; add curl-missing troubleshooting;
  npm bump "conditional" → mandatory; document nightly CI trigger.
- `docs/spec.md` §4/§9: structure listing (8+ modules unlisted, ranges.rs
  flat-ref, api facade split, docs/ listing), HTTPUpgrade-vs-xray claim,
  server port vestige. (Spec is SUPERSEDED-marked; fix facts, keep banner.)
- ADR-010 status → `Superseded by ADR-013`; ADR-005 body scrub of
  frontend/HTTP refs; ADR-008 tokio `fs` feature note.
- Intent doc: mark superseded claims (IP2Location→db-ip, speed-test ban now
  opt-in, browser/file-download refs) — annotate, don't rewrite history.
- AGENTS.md: add `sharelinks` to export formats.
- `geoip-version.txt`: add trailing newline (DOC-72).
- GitHub: repo description drops "browser UI"; close stale issue #6; add
  topics. (Manual, non-code — do alongside PR.)
- `build.rs`/`xray.rs` nits DOC-71/73 (read_all error swallow, zip double-read):
  verify-then-fix if real.

### F-23 Remove dead server-era types
- Source: DOC-13. `ResultsPayload/StatusPayload/RangesPayload/
  XrayStatusPayload/XrayDownloadResponse/RegisterRequest/RegisterResponse/
  ExportConfigRequest/ExportConfigResponse` in `src/api/types.rs` are unused
  since ADR-013. Delete + `cargo clippy` confirms. (ASK-FIRST technically
  touches `src/api/` — bundled into the refine gate.)

## P4 — Export formats & distribution

### F-24 Export format gaps (additive only — no breaking change to existing output)
- Source: ARCH-158..166/172..178.
- ADD (new `--export-format` values, additive): `v2ray` (JSON, huge
  Win/Android base — parsing infra exists), `shadowrocket`, `quantumult`
  (small, loyal iOS bases). Each = parser mapping + template + tests.
- FIX (bugs in current output): sing-box/clash omit grpc `mode`; IPv6
  endpoints silently dropped from bundles (drop loudly or support — ticket
  decides; recommendation: emit with warning count); sing-box/clash silently
  skip malformed URIs (count + stderr warning); `config_index` leaks into
  JSON export (internal field — strip or document; recommendation: strip).
- DEFER (needs user call — changes existing output shape): full-config
  sing-box wrapper / Clash proxy-groups+rules+DNS (ARCH-172/173 "high").
  Recommendation: ship as NEW values (`singbox-full`, `clash-full`)? or change
  in place? → refine gate.
- Outright: `udp` flag on Clash proxies (ARCH-178 low — add, trivial);
  WS `packet_encoding` (ARCH-177 — add if one line); Stash (covered by Clash,
  skip per agent).

### F-25 npm wrapper hardening
- Source: ARCH-167/170/171.
- ADD: missing-binary guard in `bin/cf-scanner.js` (silent failure today);
  error categorization (platform vs network vs checksum); download progress;
  document minimum Node version in README.
- PROPOSAL (needs user call — new dist targets): musl/Alpine support
  (Docker/CI demand) — requires dist matrix + CI work; ticket as proposal,
  default = document the glibc requirement clearly.
- NOT DOING: macOS targets (deliberately dropped, ADR-009).

### F-26 Release pipeline hardening
- Source: ARCH-71/73/74/75 (+ old-review leftovers re-checked).
- MSI ships `xray.exe` (self-contained claim is currently false — verify in
  `wix/main.wxs` + `dist-workspace.toml`, then fix).
- Gate releases on the tagged commit (test+clippy in `release.yml`),
  `--locked` everywhere, toolchain pin in checks, cross-compile check for the
  3-target matrix + `dist-bundle-xray` feature build.
- `concurrency: cancel-in-progress` on release.yml.
- VERIFY FIRST: "GeoIP TOFU" (ARCH-76) looks FIXED already (build.rs pins
  SHA-256 + fails closed) — ticket = verify + close, not implement.
- CI size guard: no tracked file > 1MB (placeholder-brick protection).

## P5 — Architecture paydown (no behavior change)

### F-27 Structural refactors (each its own ticket, each ≤5 files)
1. Split `configs.rs` (1,975 lines, 5+ responsibilities: URI parse ×4,
   subscription fetch, Xray-JSON normalize) along its natural seams.
2. Split `validate()` monolith (~100-line, 6 concerns) into per-area fns.
3. Dedupe ~200 lines of CDN/WARP probe-loop structure (ARCH-143) behind one
   generic driver — WITHOUT regressing the intentional separations
   (ARCH-91/92/94 say loops/dispatch are correctly separate; dedupe only the
   mechanical worker/plumbing part).
4. `ScanController` god-object (13 fields): extract cohesive groups
   (phase-2 handle, speed handle, warp cache) — mechanical.
5. Reconcile `TunnelProbe`/`TunnelOpener` overlap (ARCH-147) + surface
   `WarpRegisterError::detail` (ARCH-120) + harden `WizardInterrupted`
   matching (ARCH-121).
6. Export: adding a format touches 4 locations (ARCH-159) — registry pattern
   so F-24 additions are one-spot changes.
7. Perf micros (only with before/after reasoning, no benchmarks infra):
   `accepted_codes` clone per probe → `Arc`; `Result(Box::clone)` double-clone;
   `for_each_result` whole-store clone → streaming/len+get; `Verdict`
   hot-path `Option<String>` audit; `plan_hosts_iter` Box-per-CIDR;
   `snapshot_sorted` sort-under-lock window (ARCH-79 — measure, then decide).
   Skip list (acceptable by design, documented in ticket): SocketCache TOCTOU
   (ARCH-132), NEXT_INDEX skip-0 (ARCH-139), `step_budgets` configurability
   (ARCH-149), transport middleware (ARCH-146 — YAGNI).

## P6 — New capabilities (proposals; deps/behavior = ask-first)

Source: ARCH capability gaps + TEST-26 (live smoke never runs in CI).
- C-1 Concurrent subscription validation command (validate a sub URL's
  configs end-to-end, offline-testable with FakeSub + loopback).
- C-2 Scheduled/auto-refresh of ranges (`ranges refresh` on a timer flag?
  or document cron/systemd) — recommend docs-first.
- C-3 QUIC/HTTP3 probing, DNS-over-HTTPS probing, Trojan-Go transport —
  each needs NEW DEPENDENCIES (ask-first per ticket; default = defer with
  rationale unless user explicitly pulls).
- C-4 IPv6 end-to-end completeness pass (scan→verify→export incl. bundles).
- C-5 Live-evidence CI job (opt-in, secrets-gated) for phase-2/WARP/registration.
- C-6 Termux/musl install docs + troubleshooting (cheap, do it).

## Explicitly NOT doing (with reason)
- macOS targets (ADR-009, deliberate).
- Stash export (covered by Clash).
- `--quiet/--no-progress` (stderr already TTY-gated; YAGNI).
- Transport middleware pattern, `step_budgets` configurability (YAGNI).
- Speed-test-by-default (intent ban stands).
- Any version bump / tag / publish in this program (user-gated; this ships as
  `[Unreleased]` + one PR).
- New-network-dependency features (C-3) unless explicitly pulled in refine.

## Count
P0: 14 fixes · P1: 2 · P2: 3 · P3: 4 · P4: 3 · P5: 1 (7 sub-tickets) ·
P6: 6 proposals · Security: clean, no action.
