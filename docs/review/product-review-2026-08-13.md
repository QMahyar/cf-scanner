# CF-Scanner — Finished-Product Review (10-Agent Audit, v0.3.0)

Date: 2026-08-13. Base commit: `dd0caa3` (release: bump version to 0.3.0).

Ten independent read-only review agents each audited one product dimension. Every
agent self-rated their report; nothing rated >= 5/10 was discarded. This file is
the complete review, and every finding/recommendation below is the implementation
contract for the `review/*` branches.

## 1. Executive Summary

CF-Scanner is a genuinely strong, contract-first Rust product: 193-200 tests (all
green), clippy/fmt-clean, 0 known vulns (cargo audit clean across 254 crates), 3
real releases (v0.1.0 -> v0.3.0) through a real cargo-dist pipeline, real WireGuard
handshake tests over loopback, and a custom accessible UI. The core engine is
8-9/10 quality. What keeps it from being a finished product: one reachable OOM
crash vector (flagged by 5 of 10 agents), lossy SSE with no reconnect semantics
(flagged by 4 agents), no DNS-rebinding protection on the unauthenticated
localhost API (3 agents), docs/spec frozen at DRAFT with a dead htmx/Pico stack
(3 agents), and macOS/MSI distribution gaps (packaging agent).

| # | Domain | Rating | Verdict |
|---|--------|--------|---------|
| 1 | Packaging & Release | 6.5/10 | Tag/CI discipline excellent; MSI not self-contained; macOS unsignable |
| 2 | Capabilities | 8/10 | All 9 spec success criteria delivered; WARP registration missing from UI |
| 3 | Code Quality & Architecture | 8.5/10 | Disciplined; unbounded task fan-out + god-module engine.rs |
| 4 | UI/UX | 6.3/10 | Polished + accessible-by-intent; live-render jank, cancel lies, light-mode fails AA |
| 5 | Backend/API | 7/10 | Contract-first and well-tested; rebinding hole, preset-Full OOM, lossy SSE |
| 6 | Testing & QA | 7/10 | Deep deterministic suite; zero coverage measurement, xray lifecycle untested |
| 7 | Security | 5/10 | Would not pass pro review: rebinding, OOM, file-read primitive, keys in profiles API |
| 8 | Performance | 6.5/10 | ~5-13k probes/s phase-1; 2 avoidable cliffs (fan-out, per-attempt xray spawn) |
| 9 | Docs & DX | 7/10 | Best-in-class AGENTS/ADRs; spec is stale DRAFT, README has no download path |
| 10 | Reliability | 6/10 | Poison-proof engine; OOM vector, silent UI hang, orphaned xray, no graceful shutdown |

## 2. Cross-Cutting Themes (appear in 2+ agent reports — fix these first)

1. **Unbounded task fan-out -> OOM** (Agents 3, 5, 7, 8, 10). One `tokio::spawn`
   per (host x port) into an unbounded JoinSet; semaphore gates execution, not
   allocation. `Count(100_000)` is capped; `Preset::Full` (~1.5M hosts) and user
   CIDRs like `0.0.0.0/0` are not. 300MB-1.5GB RSS; worst case process abort.
   **Fix: worker pool of `concurrency` tasks draining an iterator; stream
   `PlanItem::Every` hosts lazily.**
2. **SSE is lossy and non-recovering** (Agents 3, 4, 5, 8, 10). `broadcast(1024)`,
   lagged -> dropped silently, no `Last-Event-ID` replay, UI never polls
   `/api/status`. A slow tab or reconnect permanently loses events including
   `Finished` -> "Scanning..." hangs forever.
3. **Unauthenticated localhost API lacks Host validation** (Agents 5, 7). DNS
   rebinding -> any website can start scans, read results, and reach the phase-2
   local-file read + SSRF (subscription fetch of attacker URLs).
4. **Docs frozen at DRAFT, htmx/Pico dead** (Agents 2, 9). spec.md says DRAFT +
   htmx 2.2.4 + Pico.css 2.1.1 — zero traces in code (custom vanilla design system
   since 0.3.0). Intent/README/ADR-005 repeat it. Task trackers disagree in
   opposite directions.
5. **Cancelled scans are indistinguishable from completed** (Agents 4, 5). Cancel
   -> `Finished` event -> UI shows 100% "Done".
6. **xray subprocess lifecycle gaps** (Agents 6, 10). No Ctrl+C handler -> up to 8
   orphaned xray children on hard kill (worst on Termux); stale `trial-*/config.json`
   with plaintext credentials left on disk; stderr discarded (arch-mismatch
   diagnosis impossible); corrupt binary costs 10s per attempt.

## 3. Domain 1 — Packaging & Release — 6.5/10

### Findings

- **[Major 4/10] MSI is not self-contained** — `wix/main.wxs:123-130` ships only
  `cf-scanner.exe`; xray.exe lives only in zips (`dist-workspace.toml:23`).
  Verified: MSI staging dir has 1 file; zip has the 35.6MB xray. MSI users silently
  depend on a 35MB first-use download into %APPDATA% (src/xray.rs:261-287),
  contradicting "self-contained artifacts" (release-process.md:100).
- **[Major 2/10] macOS is blocked-by-default** — 2 of 5 targets are macOS, no
  signing/notarization anywhere; Gatekeeper refuses both app and bundled xray
  (quarantine propagates). README documents only SmartScreen (README.md:62-73);
  macOS silent.
- **[Major 3/10] 5-target matrix never compiled until release** — checks.yml runs
  ubuntu-latest only; aarch64-linux + both macOS compile first at tag-push.
  `dist-bundle-xray` feature never built in CI.
- **[Minor 5/10] Release pipeline runs zero quality gates** — no test/clippy/fmt
  on the tagged commit; combined with documented `git tag -f` flow
  (release-process.md:69-74), a tag can publish unverified binaries.
- **[Minor 5/10] No `--locked`, unpinned `stable` toolchain** in
  checks.yml:17,22-28 — toolchain bump can break edition-2024 build on release day.
- **[Minor 5/10] MSI gaps** — no license inside installer (MIT compliance:
  Cargo.toml:14 `license = false`), no icon, no Start Menu entry, perMachine
  forces admin. Upgrade path itself is sound (fixed UpgradeCode + MajorUpgrade,
  wix/main.wxs:64,81-83).
- **[Minor 4/10] GeoIP mmdb unverified TOFU, fails soft** — build.rs:44-61 no
  checksum pin; on download failure builds embed an empty db with a warning — a
  release can ship without country data unnoticed.
- **[Minor 6/10] Changelog drift** — no `## [Unreleased]` after 0.3.0 cut
  (CHANGELOG.md ends at the 0.1.0 block); version-link refs missing. Tag/Cargo/
  CHANGELOG alignment itself verified correct.
- **[Minor 6/10] Local smoke test < release** — no versioned names/MSI/aggregate
  sha256 locally; AGENTS.md:34 shows stale `--tag=v0.1.0`.
- **[Minor/Nit 6/10] Stateful dist builds** — leftover real binary skips
  re-verification (build.rs:89-94); foreign placeholder deleted (build.rs:141)
  can brick next build; restore relies on human discipline, no pre-commit guard.
- **[Nit 5/10] No provenance/SBOM/cargo-deny** — only `cargo audit`; dist installer
  fetched via `curl | sh` pinned v0.32.0 (TOFU).
- **[Nit 6/10] No `concurrency: cancel-in-progress`** in release.yml — tag-force
  fix flow can race `gh release create`.

### Strengths

Tag-as-single-source-of-truth enforced (9/10) - immutability doctrine + rollback
plan (8/10) - xray bundling fail-closed, doubly .dgst-verified (9/10) - verified
real artifact: 21.5MB zip, sha256 self-consistent (8/10) - Cargo.lock committed,
cargo audit mandatory (7/10) - clever 0-byte placeholder scheme (7/10) - sound
Windows upgrade path (7/10) - stranger-could-run-a-release docs (8/10).

### Domain-1 Recommendations (implementation contract)

1. Fix macOS distribution: signing requires Apple certs (not implementable
   without them) -> drop the two macOS targets and record the decision in an ADR
   + release-process.md matrix update.
2. Make the MSI self-contained: ship `bundled/xray.exe` in the installer (WiX
   component), restore the license component, update "self-contained" claim.
3. Cross-compile checks in CI + `--all-features` build of the dist feature.
4. `--locked` everywhere + pin the toolchain in checks.yml.
5. Gate the release on the exact tagged commit (test+clippy jobs in release.yml).
6. Pin the GeoIP mmdb SHA-256 in `data/geoip-version.txt`; hard-fail the build
   instead of embedding an empty db.
7. Restore `## [Unreleased]` in CHANGELOG.md; add version-link refs.
8. Guard the placeholder restore (CI size check: no tracked file > 1MB).
9. Add GitHub Artifact Attestations to the host job.
10. Add `concurrency: cancel-in-progress` to release.yml.

## 4. Domain 2 — Capabilities & Product Completeness — 8/10

All 9 spec success criteria (docs/spec.md:170-187) delivered: 127.0.0.1:8765
serve; phase-1 presets/count/ports/exclusions/stop-N; phase-2 embedded xray +
fragment presets + SNI verdicts; WARP pools x ports probes + wgconf verify incl.
AmneziaWG; opt-in v0a884 registration (live-proven 2026-08-13); last-scan-only +
reset + sort/copy/save; offline GeoIP country + phase-2 colo; 5-target dist
matrix; README caveats. All 5 spec decisions honored.

### Gaps

- **[Major] Registration not in the browser UI** — `warp-config generate|export`
  is CLI/wizard-only (main.rs:380-405); UI hardcodes `generate_config: false`
  (embed/index.html:1055-1056); server sanitizes the fields out of profiles
  (server.rs:268-274). The headline "opt-in WARP registration" is unreachable
  from the flagship interface. -> new `/api/warp/register` endpoint + UI form.
- **[Major] No automated live evidence in CI** — real phase-2/xray/registration
  proof lives only in manual checkpoint notes. -> documented QA runbook / opt-in
  CI job.
- **[Minor] Stale docs vs shipped reality** (spec htmx/Pico, "Country+City" mmdb,
  `util.rs` never created, intent "IPv4 only" vs opt-in v6, "14 subnets" vs 15).
- **[Minor] Dead API surface** — `WarpConfig.generate_config` +
  `warp_plus_license` serialized/validated, never consumed. -> remove the fields.
- **[Minor] Hardcoded v0.2.0 pill + placeholder GitHub URL** in
  index.html:501-502,796 (patched at runtime; `https://github.com/user/cf-scanner`).
- **[Minor] `--warp-probes` accepted in CDN mode** (main.rs:157-159) — silently
  no-ops. -> mode-gate it.
- **[Minor] xray stderr discarded** on spawn failure (xray.rs:184-186).
- **[Minor] Coverage bar unenforced** — spec:150 claims >=85% llvm-cov; no run
  exists. -> enforce in CI.
- **[Minor] Port-collision fallback unimplemented** — serve fails hard on busy
  8765. -> friendly EADDRINUSE message.
- **[Minor] `unused/trial-0,1` leftover dirs** in working tree.

### Domain-2 Recommendations (implementation contract)

1. WARP registration in the browser UI (new endpoint + UI form) OR remove dead
   fields and document CLI-only. -> implement BOTH: new endpoint + UI form, and
   remove the dead `generate_config`/`warp_plus_license` fields.
2. Documented QA runbook for live phase-2/WARP/registration.
3. Fix stale docs (one docs-freshness commit).
4. Drive the version pill from build-time values; fix the placeholder GitHub URL.
5. Capture xray stderr into the failure error.
6. Mode-gate `--warp-probes`.
7. Implement the port-busy fallback message.
8. Decide the coverage bar: run llvm-cov once, record, add CI check.
9. Clean up `unused/` dirs.
10. Profiles persistence across restarts (small JSON in data dir).

## 5. Domain 3 — Code Quality & Architecture — 8.5/10

### Findings

- **[Major 5/10] Unbounded probe-task fan-out** (engine.rs:264-324, 385-449,
  532-611) — every combo spawns a task into JoinSet; Full ~1.5M parked tasks,
  0.5-1.5GB heap before a probe runs; `plan_hosts` materializes the whole Every
  Vec (engine.rs:729-733).
- **[Major 6/10] Two CIDR parsers + two endpoint parsers** — `ranges::parse_cidr`
  (ranges.rs:98-133) vs `api::types::validate_cidr` (types.rs:344-370);
  `engine::parse_endpoint` (engine.rs:775-793) vs `validate_endpoint`
  (types.rs:373-399). Already disagree: `::/0` valid in one, rejected in the
  other — semantic in the wrong layer.
- **[Major 6/10] engine.rs = 1,559-line god-module** — spec predicted
  `engine/cdn.rs` + `engine/warp.rs` + `engine/warpgen.rs` (spec.md:71-75); CDN/
  WARP probe loops are ~85 lines each differing only in probe body.
- **[Minor 6/10] 5x duplication of pure helpers** — Hinnant civil date
  (ranges.rs:539-556 vs warpgen.rs:419-433 — cryptographic-adjacent, WARP
  registration rejects wrong `tos`), `unix_now`, `hex_lower` (build.rs:199 vs
  xray.rs:289), `.dgst` parsing (already subtly different tolerance),
  `make_executable`.
- **[Minor 7/10] Panic points + poison inconsistency** — `main.rs:418,421`
  unwraps in CLI JSON stream; `cli_wizard.rs:344` unwrap on user input;
  `server.rs:103,246` `.expect("ranges state lock")` while engine recovers from
  poisoning at ~20 sites. Two poison policies in one binary.
- **[Minor 7/10] Stop-condition overshoot** — counters checked pre-probe with
  Relaxed ordering; cap/found overshoot by <=concurrency; tests only pin
  concurrency=1.
- **[Minor 7/10] Lagged broadcast receivers silently lose events**
  (engine.rs:178 `Err(_) => continue`; server.rs:194 lagged -> None).
- **[Nit 8/10]** — `spawned` counts completed attempts not xray spawns
  (engine.rs:529,579); magic `0x5EED`; AGENTS.md claims `#![deny(warnings)]` that
  doesn't exist; stale "Task N" module docs; tokio `"full"` features pull
  unneeded deps.

### Strengths

Contract-first separation is real — `ScanConfig::validate()` 17-variant typed
`ConfigError`, engine returns domain types, only api types serialized (9/10) -
5 injectable transport seams, network-free tests (10/10) - stop-condition +
cancellation machinery incl. RAII ResetGuard (9/10) - timeout discipline total —
every network touch bounded (10/10) - security-mindedness — redaction, 0600
identity, https-only redirects, v6 /0 rejection (9/10) - test depth exceptional —
golden 148/92/64B WARP vectors, real loopback boringtun handshake, scripted
SOCKS5 server, axum mock registration (10/10) - typed errors internally, anyhow
at boundaries (9/10) - fmt+clippy clean, zero TODO/FIXME/dead code, one test-only
unsafe (10/10).

### Domain-3 Recommendations (implementation contract)

1. Bound the probe fan-out: replace spawn-per-item with `concurrency` worker
   tasks pulling work items; stream `PlanItem::Every` hosts instead of
   materializing the Vec.
2. Split `engine.rs` into `engine/cdn.rs`, `engine/warp.rs`, `engine/phase2.rs` +
   `mod.rs` per the spec's own plan; extract the two near-identical probe loops
   into one generic driver.
3. Unify CIDR/endpoint parsing: `validate_cidr`/`validate_endpoint` delegate to a
   single parser (shared `parse_endpoint` lives in api/types.rs).
4. Extract a `util` module for the duplicated pure helpers (Hinnant civil date,
   unix_now, hex_lower, .dgst parsing, make_executable).
5. Single-sourced poison policy: recover from poisoning everywhere (server
   included).
6. Remove production unwraps: main.rs:418,421; cli_wizard.rs:344.
7. Document the stop-condition overshoot (or post-probe re-check); pin an
   overshoot test at concurrency=4.
8. Trim tokio features from "full" to the used set (keep `signal` — Ctrl+C
   handling lands in the CLI branch).
9. Close the lagged-event gap: on `Lagged`, fall back to snapshotting
   results/summary at completion; larger channel for Full scans.
10. Naming/sweep: rename `spawned` -> `completed`; comment `0x5EED`; update stale
    "Task N" module docs.

## 6. Domain 4 — Frontend UI/UX — 6.3/10

### Findings

- **[Major 4/10] No render throttling** — full sort + full `tbody.replaceChildren()`
  per SSE result event (render() index.html:1115-1162); histogram O(6n) rebuild;
  lagged events silently dropped server-side -> table can permanently disagree
  with summary. No rAF/interval coalescing, no virtualization, no keyed rows.
- **[Major 4/10] Reconnect/recovery hole** — no `es.onerror` handler, no resume;
  `/api/results` fetched only at load; `is_running` from /api/status never used —
  refresh mid-scan can't restore live state.
- **[Major 3/10] Screen-reader live-region spam** — `#scan-status` role=status
  rewritten per progress event (1330); `#results-live` set every render() (1161)
  — AT users announced at continuously (anti-WCAG 4.1.3).
- **[Major 3/10] Progress invisible to AT** — `#progress-track` no
  role=progressbar / aria-valuemin/max/now; `#progress-text` not a live region.
- **[Major 5/10] No client-side start guard** — second click -> raw JSON error
  body displayed with no error state; running card loses accent border mid-scan.
- **[Major 4/10] Cancel misrepresented as success** — cancel -> Finished -> bar
  to 100% + "Done"; no "Cancelled" state exists.
- **[Major 4/10] Reset enabled during scan** — ghost results reappear under a
  "cleared" banner.
- **[Major 5/10] Light theme fails WCAG AA** — `--muted #64748b` on
  `--bg #f2f5f9` = 4.35:1 FAIL, on surface-2 = 4.23; `--success #059669` on
  white = 3.77:1 FAIL; dark theme passes everything.
- **[Major 4/10] Validation errors never reach fields** — `.field-error` CSS is
  dead code; errors go to banner only; no aria-describedby wiring.
- **[Minor 5/10] Copy != displayed order** — table latency-sorted; Copy
  serializes raw insertion order (1239).
- **[Minor 5/10] Mobile table loses identity** — no sticky IP column in 7-column
  scroll.
- **[Minor 5/10] Profile upsert silently overwrites** — no "replacing existing
  profile" warning.
- **[Minor 6/10] Version hardcoded twice + runtime innerHTML patch** — only
  non-static innerHTML in the app (1670).
- **[Minor 5/10] Jarring auto-scroll on finish** (1348).
- **[Nit 6/10] Theme button aria-pressed semantics wrong** for 3-mode cycle.
- **[Nit 6/10] `color-mix` no fallback** (~12x) — degrades on <Chrome 111/
  Safari 16.2; no CSP header.

### Strengths

XSS posture genuinely disciplined — every API value via textContent, CSV
formula-injection neutralized, only non-static innerHTML is version patch (9/10)
- theme system ahead of the research report — tri-state, localStorage,
matchMedia, fully-AA dark tokens (9/10) - latency masking solid — determinate/
indeterminate, X-of-Y + ETA, rate, title updates, sticky header (8/10) - a11y
scaffolding above the norm — skip link, sr-only, keyboard sortable headers with
aria-sort, forced-colors, reduced-motion, radiogroup segmented control, 44px
targets, focus-visible (7/10) - feedback design — 4-state clipboard, toasts,
empty state + CTA, Retry preserves config, density toggle, histogram (8/10) -
results table core 7/10 - export with ISO-8601 filenames + IPv6 bracketing 8/10 -
Ctrl+Enter + Escape shortcuts 8/10 - form affordances — per-mode disable with
"why" notes, 443<->2408 port swap, fragment auto-fill 7/10.

### Domain-4 Recommendations (implementation contract)

1. Coalesce live table rendering: buffer verdicts, re-render max every ~100ms
   (or per-rAF), key rows by ip:port, reconcile against /api/results on
   lagged/reconnected streams.
2. Rework scan-state machine: disable Start while running, disable Reset while
   running, real "Cancelled" terminal state (no 100% bar, "Cancelled — N working
   retained", no Retry button).
3. Fix AT live regions: announce only on scan start/end/cancel/sort; progressbar
   role + aria-valuemin/max/now; #progress-text polite region.
4. Light-theme contrast pass: `--muted` >= 4.6:1 (e.g. #5b6b84), `--success` ->
   #047857; re-verify all small-text combos.
5. Wire field-level validation: on-blur checks, apply `.field-error` CSS,
   aria-describedby, parse API error JSON -> styled message.
6. SSE robustness: es.onerror + "reconnecting..." state, defensive JSON.parse,
   use is_running from /api/status to restore live state.
7. Sticky IP column + horizontal-scroll affordance on mobile.
8. Make Copy honor the displayed sort order (or add copy-format options).
9. Profile upsert warning before overwriting.
10. Polish backlog: no auto-scroll-on-finish, toast close affordance, version
    from /api/status authoritative only, color-mix fallbacks.

## 7. Domain 5 — Backend HTTP API & Server — 7/10

### Findings

- **[Major/Security] No Host/Origin validation; DNS-rebinding + CSRF + SSRF
  surface** (server.rs:146-163) — any host header accepted; phase-2 subscription
  fetch of attacker-chosen URLs (engine.rs:637-651) = SSRF against local
  services. 127.0.0.1 bind shrinks but doesn't close.
- **[Major] Preset-Full bypasses the OOM cap** — the cap comment at types.rs:
  259-264 exists because "an unauthenticated API call cannot abort the process" —
  but only `Count` is bounded; `Preset::Full` + v6 ~ 10M+ tasks.
- **[Major] SSE lag = silent permanent data loss** — no replay on connect; UI
  snapshots /api/results only at page load.
- **[Major] ADR-005 discipline half-held** — engine imports `api::types` and
  builds `Verdict`/`ScanEvent` itself (engine.rs:15-18, 296-306); there are no
  domain types. Mitigated by serde round-trip tests + ask-first rule.
- **[Minor] 202-then-Failed race on concurrent start** (server.rs:173-182 TOCTOU)
  — loser only revealed via SSE event.
- **[Minor] Error payload shape inconsistent** — `{"error","message"}` from
  ApiError but axum's own rejections return plain text.
- **[Minor] Cancelled runs indistinguishable from completed** — no `cancelled`
  marker on ScanSummary; in-flight probes/phase-2 xray not aborted (watch is
  cooperative-only).
- **[Minor] List fields unbounded** — ports/exclude/custom_cidrs/configs/snis
  uncapped; duplicate ports not deduped.
- **[Minor] Contract versioning ad hoc** — unversioned /api, no stability policy
  written down.
- **[Nit] Dev/release UI divergence** — `.fallback_service(ServeDir("embed"))`
  (server.rs:162) serves live files in dev vs embedded copy in release; blocking
  `std::sync::RwLock` in async handlers; no graceful shutdown (main.rs:447);
  CustomFragment unvalidated until mid-phase-2.

### Strengths

Centralized typed validation defense-in-depth (9/10) - status-code semantics
correct + every one integration-tested (9/10) - one event source, three clients
— SSE/NDJSON/wizard share the exact contract (8/10) - bind discipline —
127.0.0.1 hardcoded, no --host flag (9/10) - secrets hygiene — redaction incl.
Windows paths, profile sanitization, CSV injection neutralization (9/10) - engine
concurrency safety — RAII ResetGuard, semaphores, reset-while-running no-op
(8/10) - test depth — raw HTTP/1.1 integration tests, SSE framing, 409 race,
50-writer profile concurrency (9/10) - timeouts everywhere (8/10) - UI contract
alignment exact (8/10) - session-scoped state, refresh keeps last-good (8/10).

### Domain-5 Recommendations (implementation contract)

1. Host-header allowlist + Origin/Sec-Fetch-Site checks — the single highest-
   impact change; closes rebinding/CSRF/SSRF.
2. Bound Preset-Full scans — worker-pool (task per semaphore permit) instead of
   task-per-host (engine branch), plus list-field caps.
3. Make SSE lossless — per-connection replay on connect or lag-triggered polling
   of /api/results; at minimum surface a lag indicator.
4. Atomic try_start in the engine (server awaits authoritative 409).
5. Add `cancelled`/reason to ScanSummary — UI/CLI distinguish stop-from-cancel.
6. Uniform error envelope — rejection handler so every 4xx returns
   {"error","message"}.
7. Cap + dedupe list fields in validate() — ports, configs, snis, exclude,
   custom_cidrs.
8. Document the API stability policy — additive-fields-with-defaults policy,
   recorded in an ADR.
9. Bound SSE connections and drop stale receivers.
10. Reconcile dev/release UI serving; graceful shutdown.

## 8. Domain 6 — Testing & QA — 7/10

### Findings

- **[Major] No coverage measurement anywhere** — no tarpaulin/llvm-cov config, no
  CI job, spec's >=85% claim unenforced.
- **[Major] `XrayTunnelProbe` subprocess lifecycle untested** — spawn/kill/
  cleanup/socks-wait is the most failure-prone path; verify.rs has 2 trivial
  tests.
- **[Major] CLI agent execution untested** — 18 main.rs tests cover parse +
  build_scan_config only; the actual `scan` NDJSON agent, summary, exit codes,
  `ranges refresh`/`serve` have zero tests.
- **[Major] Test isolation flaw** — refresh tests write to and delete the REAL
  data dir (`paths::refreshed_ranges_path()`, ranges.rs:1387-1397, 1428-1439) —
  can destroy a developer's refresh file; warpgen solved this via
  `CF_SCANNER_DATA_DIR` (warpgen.rs:622-630).
- **[Minor] No dev-dependencies** — no proptest/quickcheck/tempfile/criterion;
  zero property tests, fuzz targets, benchmarks.
- **[Minor] Geo DB tests self-skip** — return early when mmdb absent
  (geo.rs:77-98) — pass vacuously; no fallback-state test.
- **[Minor] paths.rs untested** incl. the Windows exe-name branch.
- **[Nit] Misleading ignored test** — `vless_fixture_dials_its_own_server` never
  dials (live_smoke.rs:33-41); duplicates a unit test, can never fail.
- **[Minor] Timing-based tests** — 50-500ms sleeps + polling (engine.rs:1039-
  1064, 1469-1514; server.rs:602-624) — wide margins but nonzero flake risk.
- **[Minor] Wizard ~untested** — 1 test; no prompt seam.
- **[Nit] 0 doc-tests** despite `pub` lib.

### Strengths

Full injectability — 5 traits with scripted fakes, tests provably never touch
network (10/10) - engine state machine coverage — 32 tests incl. found/cap/
exhaust, mid-scan cancel, concurrent-run rejection, reset-while-running,
phase-2 SNI combos, redaction (9/10) - real crypto round-trips — full WireGuard
handshake over loopback with boringtun responder (9/10) - loopback mock API tests
— registration flow asserted on method/path/headers/bodies (9/10) - fixture
matrix — vless/vmess/ss/trojan URIs, wgconf INI + wg:// + wireguard://
round-trips (9/10) - deterministic SplitMix64 sampling tests (9/10) - checksum
pipeline tested offline incl. mismatch rejection (9/10) - live smoke properly
gated behind #[ignore] + env credential (9/10) - CI gates: all-targets build,
test, clippy -D warnings, fmt, audit (9/10).

### Domain-6 Recommendations (implementation contract)

1. Add coverage measurement (llvm-cov) to CI with a failing threshold; report
   per-module.
2. Test `XrayTunnelProbe` end-to-end without a real xray: fake binary via
   `CF_SCANNER_DATA_DIR` + temp dir; assert spawn/kill/trial-dir cleanup.
3. Move the two `refresh_to_disk` tests off the real data dir — respect
   `CF_SCANNER_DATA_DIR` in paths.rs (not just warpgen).
4. Add an integration test for the CLI `scan` agent: capture stdout, assert NDJSON
   lines + summary + exit code.
5. Convert the self-skipping geo tests into deterministic fixtures, or assert the
   fallback state explicitly.
6. Replace the misleading ignored `vless_fixture_dials_its_own_server` with a
   genuinely network-touching smoke, or drop it.
7. Add property tests for the highest-math modules: CIDR exclusion split and
   range sampling distinctness.
8. Add `paths.rs` unit tests incl. the Windows exe-name branch.
9. Reduce timing sensitivity: replace fixed sleeps with handshake/state polling.
10. Add doctests on 2-3 key `pub` items (e.g. parse_uri, render_wgconf).

## 9. Domain 7 — Security — 5/10

### Findings

- **[Major 2/10] DNS rebinding — full API access from any website** — no Host
  allowlist/CORS/auth token (server.rs:133-164); can read results/profiles, start/
  cancel scans. JSON content-type + absent CORS blocks naive CSRF, PNA preflights
  blunt modern browsers, but PNA coverage is partial.
- **[Major 3/10] Unauthenticated OOM via port fan-out** — `100_000 hosts x 1000
  ports` = 100M spawned futures; no rate limit on scan starts; phase-2 multiplies
  xray spawns by unbounded snis.
- **[Major 3/10] Local file-read primitive** — phase-2 configs: non-URL entries
  are `fs::read_to_string`'d (engine.rs:657-663), reachable unauthenticated via
  POST /api/scan; existence oracle + disclosure of xray-JSON-shaped files; CLI is
  the legitimate user — HTTP API should not be.
- **[Major 4/10] WireGuard private keys exposed via GET /api/profiles** — sanitize
  clears generate_config/warp_plus_license but deliberately keeps `warp.wgconf`
  (server.rs:268-274) -> any local process/user reads WARP private keys; rebinding
  page exfiltrates them.
- **[Minor 5/10] xray trial configs on disk** — config.json written 0644 (umask
  default, xray.rs:178); hard kill leaves credentials world-readable indefinitely;
  identity.json 0600 Unix-only (warpgen.rs:262-277).
- **[Minor 5/10] GeoIP mmdb unverified** — TLS fetch, size-heuristic only
  (build.rs:227-231), cached in system temp; shells out to curl from PATH.
- **[Minor 5/10] 0-byte placeholders in git, unprotected** — a dist build +
  `git add -A` commits a ~60MB binary; relies on human discipline.
- **[Minor 6/10] Misc** — no rate limiting / unbounded profiles map (<=2MB bodies
  each) -> memory DoS; phase-1 TLS NoVerify accepted-risk undocumented; WARP
  shape-only classification false-positives documented but not in docs;
  CustomFragment unvalidated; profile names allow `/`; `pick_ephemeral_port`
  TOCTOU self-healing; loopback plaintext keys undocumented.

### Strengths

cargo audit clean — 0 vulns, all key crates current (9/10) - input validation
genuinely thorough (9/10) - xray supply chain — pinned version, .dgst
verification, no PATH resolution, fixed args, no shell, kill_on_drop (9/10) - no
key material in logs, redaction tested (8/10) - loopback-only bind, no escape
hatch (9/10) - UI hardening — textContent everywhere, no stored XSS (8/10) - HTTP
hygiene — https-only, redirect caps, 64MiB cap, 20s timeouts, manual SOCKS5 with
length checks (8/10) - OsRng keygen, fresh receiver index per probe (8/10) -
atomic writes + graceful mmdb degradation (8/10).

### Domain-7 Recommendations (implementation contract)

1. Reject non-loopback `Host` headers (middleware allowlisting 127.0.0.1[:port],
   localhost[:port], [::1][:port]) — kills DNS rebinding outright.
2. Bound task fan-out: cap `ports` count (<=64) and dedupe; keeps the
   "unauthenticated API call cannot OOM" promise.
3. Ban local file paths in phase-2 configs over the HTTP API (URLs/URIs only;
   file paths remain CLI-only).
4. Stop returning wgconf keys from the API: mask key fields in profile GET
   responses; real config stays in the engine's scan path.
5. Per-process random API token printed on serve start (or Origin/Sec-Fetch-Site
   check) as belt-and-braces on top of #1. -> Origin/Sec-Fetch-Site check
   (token adds UX friction).
6. Write xray trial configs with 0600 and add cleanup on process exit (or a
   startup sweep of stale trial-* dirs).
7. Pin and verify the mmdb checksum in build.rs (extend data/geoip-version.txt),
   matching the xray standard.
8. Stop tracking the 0-byte placeholders: add a CI check that no committed file
   exceeds ~1MB.
9. Rate-limit /api/scan and cap the profiles map (e.g. 100 entries).
10. Validate `CustomFragment` strings (`^\d+(?:-\d+)?$`) and cap SNI list length;
    document the NoVerify TLS and shape-only WARP classification as accepted
    risks in docs/.

## 10. Domain 8 — Performance — 6.5/10

### Findings

- **[Major] Unbounded task fan-out** — ~300-900MB peak RSS on Full + 1.5-4.5s
  spawn CPU before steady state; late-bail tasks still pay spawn+acquire.
- **[Major by design] Phase-2: one xray subprocess per attempt, ceiling ~8
  concurrent** — mkdir + config write + spawn + socks poll (up to 10s) + handshake
  + kill + rmdir per (candidate x config x SNI); default 3 -> ~3-8 attempts/s;
  500 candidates x 2 combos = 2-6 min.
- **[Major at scale/Minor for defaults] `insert_sorted` O(N) memmove under one
  global Mutex per verdict** (engine.rs:765-771) — ~1-2s pure memmove+contention
  at 20K found; trivial at default stop.found=20.
- **[Minor] Per-probe allocations in hot loop** — `PROBE_SNI.to_owned()` +
  ServerName per probe, `e.to_string()` per refuse (the common case), Box::pin
  (probe.rs:88-111); ~3M+ allocs on Full.
- **[Minor] WARP: fresh UDP socket per probe, no pacing/retransmit** — 43K socket
  binds on full pool; 200-concurrency bursts can trip WARP rate shaping -> false
  negatives.
- **[Minor] Stop-condition check after permit** — overshoot + wakeup storm on
  Full scans.
- **[Minor] Host-list materialization** per (item, port) — up to ~8MB per largest
  range x ports.
- **[Minor] Blocking fs on tokio workers** — xray config write (xray.rs:178),
  config file read (engine.rs:658), ranges persist (server.rs:100-101).
- **[Minor] Event stream** — 30K progress events on Full; slow client -> silent
  drops.
- **[Nit] `wait_for_socks` 100ms poll** adds ~50-100ms avg per phase-2 attempt.

Expected numbers: no throughput claims in docs (good — nothing contradicted).
Realistic phase-1 ~5-13K probes/s at default 200 concurrency when endpoints
refuse fast, collapsing to ~67/s when everything times out. Quick ~ 1-2s, Full ~
3-10 min. Phase-2 ~3-8 attempts/s (dominant when enabled). WARP full pool (43K
handshakes) ~15-60s.

### Strengths

Injectable transports fully perf-testable offline (9/10) - explicit semaphore
bounds + MAX_SCAN_COUNT (8/10) - relaxed atomic counters, no hot-path lock
traffic except insert_sorted (8/10) - deterministic dedup'd sampling (8/10) -
CIDR exclusion O(E x R) at plan time (8/10) - no busy-waits, no locks held across
awaits (7/10) - JSON serialization confined to boundaries, progress throttled
(7/10) - last-scan-only store, geo lookups only per found verdict (7/10) - watch-
channel cancel (6/10).

### Domain-8 Recommendations (implementation contract)

1. Worker-pool or chunked spawning for phase-1/WARP loops (replace upfront task
   fan-out).
2. Check stop conditions before acquiring the semaphore and stop spawning once
   satisfied.
3. Batch verdict inserts (append + sort at finish instead of per-verdict O(N)
   insert under the global Mutex).
4. Cut phase-2 per-attempt overhead: compact JSON config, 20ms socks poll,
   spawn-blocking fs; document the 3-8 attempts/s ceiling.
5. Hoist per-probe allocations: ServerName built once per TlsTransport; error
   code enums instead of to_string() on refuse/timeout paths.
6. WARP: reuse the bound socket across probes_per_endpoint attempts; add jitter/
   pacing to avoid rate-limit false negatives.
7. Lazy host iteration for PlanItem::Every instead of per-(item,port) Vec
   materialization.
8. Move blocking fs ops to spawn_blocking (config write, config file read,
   ranges persist).
9. Scale event cadence: coarsen PROGRESS_EVERY at high totals and add SSE
   reconnection fallback to /api/results.
10. Release profile: thin LTO/codegen-units=1 for the shipped profile; bench
    harness for the probe loop + insert_sorted.

## 11. Domain 9 — Documentation & Developer Experience — 7/10

### Findings

- **[Major 3/10] spec.md frozen at DRAFT** (spec.md:3) while AGENTS.md/plan.md
  call it "approved"; three releases shipped.
- **[Major 3/10] htmx + Pico.css documented in 4 places, zero traces in code** —
  spec.md:46, intent:83, README.md:57, ADR-005:21 vs vanilla JS + native
  EventSource + custom design system (0.3.0).
- **[Major 3/10] Task trackers both stale, in opposite directions** — todo.md
  ends at Phase 6/Checkpoint G (missing Phase 7, Tasks 20-28, Checkpoint H);
  plan.md leaves Tasks 1-14 unchecked though implemented; neither is a trustworthy
  ledger.
- **[Major 4/10] Stale `--tag=v0.1.0` in the 3 most-read command listings**
  (AGENTS.md:34, README.md:38, spec.md:62-63) — repo is at 0.3.0; violates the
  project's own "artifact/tag/changelog never disagree" rule.
- **[Major 5/10] README missing customer essentials** — Quick Start is
  build-from-source only: no Releases download, no msi/shell/powershell links,
  no screenshot; Commands table omits `wizard` and `warp-config generate|export`;
  no troubleshooting/support/contribution/license sections.
- **[Minor 5/10] Phantom bind flag** — README.md:77/AGENTS.md:76 "unless an
  explicit bind flag is given" — no such flag exists (only --port; 127.0.0.1
  hardcoded).
- **[Minor 5/10] spec section 4 structure doesn't match tree** — engine/
  submodule layout, ci/checks.yml, data/geoip.mmdb all differ from reality.
- **[Minor 5/10] spec section 6 testing gating contradicts actual** — describes
  `CFSCANNER_TEST_XRAY=1` env; actual is `#[ignore]` + `CFSCANNER_SUB_URL`.
- **[Minor 6/10] Intent retains superseded claims** — "embedded xray-core"
  (contradicted by the doc's own correction), "14 IPv4 subnets" (15 shipped).
- **[Minor 5/10] No docs index** — ADRs unlinked from spec;
  ui-research-report.md referenced nowhere.

### Strengths

development.md current + verified against code — curl prereq, dist 0.32,
placeholder restore flow, useful troubleshooting table (9/10) - CHANGELOG
discipline — Keep-a-Changelog, entries match tags and commits (9/10) - honest
README core — 3 modes, no-telemetry promise, Termux/SmartScreen/offline caveats
(8/10) - high-quality ADRs — consistent shape, live-verified corrections embedded
(9/10) - AGENTS.md is a strong agent contract (8/10) - pinned data files match
docs — xray v26.3.27, geoip 2026-08, 8 WARP pools (9/10) - versioning chain
consistent — 0.3.0 == v0.3.0 == CHANGELOG (9/10).

### Domain-9 Recommendations (implementation contract)

1. Fix spec.md status + staleness: flip to APPROVED; correct stack/structure/
   testing sections; point to code + ADRs as current truth.
2. Purge htmx/Pico claims (README.md:57, spec.md:46, intent:83, ADR-005:21).
3. Reconcile task trackers: add Phase 7/Tasks 20-28 + Checkpoint H to todo.md;
   tick Tasks 1-14 in plan.md.
4. Replace stale `--tag=v0.1.0` (AGENTS.md:34, README.md:38, spec.md:62-63).
5. Add a real customer quickstart to README: Releases download + one-line
   installer per OS (msi/shell/powershell), screenshots, wizard/warp-config rows
   in the Commands table, short troubleshooting table, Support/Contributing
   section, license mention.
6. Add `docs/README.md` index linking spec, intent, all 7 ADRs, development,
   release-process, plan/todo, ui-research-report, review report; add ADR links
   to spec section 9.
7. Qualify or remove the phantom bind flag (README.md:77 / AGENTS.md:76).
8. Correct intent-doc leftovers: line 15 "embedded xray-core" -> "xray
   subprocess"; line 39 "14 IPv4 subnets" -> 15.
9. Add a lightweight freshness gate (grep for current version string and
   `Pico|htmx` in AGENTS.md/README).
10. Defer/annotate ui-research-report.md as a research snapshot.

## 12. Domain 10 — Reliability & Error Recovery — 6/10

### Findings

- **[CRITICAL] Preset::Full + broad CIDR = OOM abort** — `0.0.0.0/0` + Full =
  4.3B tasks; even Quick over /0 = 16.7M; Full over 10.0.0.0/8 = 16.7M; bundled
  Full (~1.5M ~ 300-600MB) borderline on Termux; accepted unauthenticated from
  any local process.
- **[Major] Panic inside server-spawned run task leaves UI stuck forever** —
  `start_scan` spawns and never awaits the JoinHandle (server.rs:177-181);
  ResetGuard clears state but nothing emits Failed; no catch_unwind anywhere.
- **[Major] Orphaned xray on hard kill** — no ctrl_c/shutdown_signal anywhere;
  SIGKILL/app-kill during phase-2 leaves up to 8 xray children running forever
  (worst on Termux/Android); Windows Task Manager kills orphan too.
- **[Major] Credentials on disk after crash** — trial dirs hold config.json with
  UUID/password (verify.rs:84-85 acknowledges); normal paths remove_dir_all, hard
  kill leaves plaintext; no startup sweep.
- **[Minor] Corrupt/mismatched binary = 10s per attempt, generic error** —
  wait_for_socks polls full 10s without watching for early child exit
  (xray.rs:204-215); cached binary never re-verified at use (xray.rs:248-251);
  stderr discarded (Stdio::null, xray.rs:185-187) — the one place the
  glibc-mismatch message would surface.
- **[Minor] Download races when xray missing** — every concurrent attempt (up to
  8) starts a 20MB download; one wins, rest fail "already exists" (xray.rs:275-
  278).
- **[Minor] Corrupt refreshed-ranges file fails the scan** — engine's
  effective_pool propagates parse error (ranges.rs:408-421) while server falls
  back to bundled; hand-edited file bricks every scan.
- **[Minor] Stop-during-startup race** — cancel between start_scan and cancel_tx
  install (after pool planning, engine.rs:257-258) is lost.
- **[Minor] EADDRINUSE raw error** — "os error 10048" with no hint; `serve --port
  0` prints port 0 instead of local_addr (main.rs:444-446).
- **[Minor] Ambiguous 0-result success** — zero found looks identical to
  network-down; `total == 0` silently wipes the previous run's results
  (engine.rs:253-255) after clear_store.
- **[Nit] Subscription fetch 20s, no retry**.
- **[Major] Default logging ERROR-only, no --verbose** (EnvFilter::
  from_default_env, main.rs:339-341) — non-technical user can't produce
  diagnostics without knowing RUST_LOG.
- **[None] Graceful shutdown** — no Ctrl+C handler, no axum shutdown_signal
  (main.rs:447).

### Strengths

Poison-proof engine state — one bad run can never brick the controller (9/10) -
panic isolation in probe tasks via JoinSet + RAII ResetGuard (8/10) - input
validation breadth (9/10) - xray in-process hygiene — kill_on_drop, kill+wait,
Drop-kill, checksum-verified downloads (8/10) - redaction discipline (9/10) -
Failed-event contract end-to-end across CLI/wizard/UI (8/10) - background ranges
refresh degrades gracefully server-side (8/10) - fail-fast verify paths (8/10) -
hard timeouts everywhere (9/10) - deterministic tests of recovery paths (8/10).

### Domain-10 Recommendations (implementation contract)

1. Cap preset scans by probe/task count (or stream hosts from the plan instead of
   spawning one task per host). -> worker pool + streaming (engine branch).
2. Make the terminal scan state lossless in the UI: poll /api/status + /api/
   results on a timer and reconcile a stuck "Scanning..." banner.
3. Surface run-task panics to clients: wrap the server-side controller.run in
   catch_unwind and emit ScanEvent::Failed.
4. Graceful shutdown + xray reaping: ctrl_c handling with a shutdown signal for
   axum; on shutdown abort in-flight attempts, kill/wait all xray children, sweep
   trial-* dirs. Add a startup sweep of stale trial dirs regardless.
5. Checksum-verify the cached xray binary at use time and detect early child
   exit: race a child.wait() so a corrupt/arch-mismatched binary fails in ~100ms
   with the actual exit code instead of 10s of polling. Surface the Termux glibc
   hint in the error.
6. Engine ranges fallback parity: make effective_pool fall back to bundled ranges
   when the refreshed file fails to parse, exactly like RangesState::load.
7. Add a --verbose flag (or default RUST_LOG=info) and forward xray stderr to
   logs (redacted).
8. EADDRINUSE + port-0 UX: friendly message on bind failure ("port 8765 in use —
   try cf-scanner serve --port X") and derive the URL from listener.local_addr().
9. Zero-candidate scans shouldn't destroy results or pass silently: warn (Failed
   or a distinct event) when the planned pool is empty or the plan yields 0
   probes, and skip clear_store for degenerate runs.
10. Poison-tolerance parity in the server (RangesState locks) and a single
    phase-2 xray download pre-flight instead of N racing downloads.

## 13. Implementation Branches (ownership map)

Each `review/*` branch owns exactly the files listed. No two branches touch the
same file. Merge order: 02 -> 01 -> 03 -> 06 -> 08 -> 05 -> 07 -> 04 -> 10 -> 09.

| Branch | Domain | Files owned (exclusive) |
|--------|--------|--------------------------|
| review/api-contract | Contract | src/api/types.rs, src/api/mod.rs; + exact lines: server.rs:270-271 (dead-field sanitize), engine.rs finish() cancelled flag, engine.rs parse_endpoint body delegation |
| review/engine-core | Engine | src/engine.rs (and its split into src/engine/*) |
| review/server-api | Server | src/server.rs, src/warpgen.rs |
| review/ui | UI | embed/index.html |
| review/cli | CLI | src/main.rs, src/cli_wizard.rs |
| review/xray | xray | src/xray.rs, src/verify.rs, src/paths.rs |
| review/qa | QA | tests/*, src/geo.rs, src/configs.rs, src/wgconf.rs, .github/workflows/checks.yml |
| review/ranges-probe | Ranges | src/ranges.rs, src/probe.rs, src/warp.rs |
| review/docs | Docs | README.md, AGENTS.md, docs/spec.md, docs/intent/cf-scanner.md, tasks/plan.md, tasks/todo.md, CHANGELOG.md, docs/README.md (new), docs/ui-research-report.md |
| review/ci-packaging | CI/Release | .github/workflows/release.yml, dist-workspace.toml, wix/main.wxs, build.rs, data/geoip-version.txt, docs/decisions/*, docs/release-process.md, docs/development.md, Cargo.toml |
