# Changelog

All notable changes to CF-Scanner are documented here, grouped by
Added / Changed / Fixed / Deprecated / Removed / Security, newest on top.

## [Unreleased]

## [0.8.0] - 2026-08-24

Ten-agent full-product review remediation: security hardening, engine
performance overhaul, API polish, CLI/UX, frontend a11y, and release-chain
integrity. All gates green (361 lib + 35 CLI + 8 integration tests, clippy
`-D warnings`, `cargo fmt`, UI `svelte-check` strict, Playwright visual QA).

### Added
- **CLI:** grouped `--help` sections (candidate/stopping/tuning/phase2/WARP),
  `--cap`→`max-probes` and `--target`→`stop-after` aliases, `--warp-wgconf`
  alias, `serve --open` (cross-platform browser launch), TTY-only live
  progress ticker for one-shot scans, `--json-errors` machine-readable
  failures, help examples block.
- **API:** machine-readable `code` field on every error envelope; typed WARP
  registration errors now map to proper statuses (timeout→504,
  rate-limit→429, rejection/server→502) instead of blanket 502; xray
  download failures use the uniform error envelope (no more HTTP 200 with
  `{success:false}`); SSE events carry an explicit `retry:` hint.
- **Resilience:** SSE stream survives broadcast lag — it replays the last
  terminal snapshot and keeps listening instead of closing (reconnect-storm
  fix); UI re-hydrates status/results when EventSource reconnects and shows
  an offline banner; EventSource handle is closed on teardown.

### Changed
- **Engine throughput:** per-worker task queues replace the shared
  mutex-guarded receiver (dispatch no longer serializes); producer uses
  backpressured `send().await` instead of a try_send/sleep poll; probe
  futures race cancellation (`select!`) so Stop takes effect immediately
  instead of after the in-flight timeout; result store flushes are O(1)
  pushes with lazy sort-on-read (was O(found²) merge churn); broadcast
  buffer 1024→4096; batch flush 64→256; per-port RNG hoisted out of hot
  loops; phase-2 shares config/candidate sets via `Arc` across workers.
- **WARP:** server public key resolved once per scan (was one identity.json
  read PER PROBE); socket cache is per-controller and injectable, never
  holds its lock across `.await`, and the global static is gone; corrupt
  persisted identity keys log a warning before falling back to bundled.
- **Fetch stack:** ranges + xray downloads share one reqwest client whose
  redirect policy enforces the SSRF guard per hop; ~200 lines of hand-rolled
  TLS/HTTP/chunked fetch code deleted; TCP_NODELAY on probe sockets;
  wait-for-xray polling backs off exponentially; trial-dir sweeps throttle
  to once per stale window and guard cleanup leaves the runtime thread.
- **Frontend:** latin-only Inter subsets (-83 KB dist), first-invalid focus
  management, `aria-describedby` wiring on all field errors, `aria-sort` on
  sortable buttons, checkbox focus rings, copy feedback via `role=status`,
  safe-area padding on the sticky action bar, live pace/ETA tick,
  Copy-all respects active filters, `tsconfig` now `strict`.

### Security
- `--warp-wgconf-file` read capped at 64 KiB before parse (OOM guard).
- Xray zip: archive and entry sizes capped at 64 MiB (zip-bomb guard);
  cached-binary memo re-stats the file so a vanished/truncated binary
  re-downloads instead of failing at spawn.
- `Origin: null` requests denied (sandboxed-frame CSRF surface); JSON body
  rejection text sanitized + truncated before echoing into error envelopes.
- Contract tightening: `deny_unknown_fields` on ScanConfig/Phase2/Warp
  payloads, custom WARP endpoints capped (2048), raw port-array precheck
  before dedupe sort, decoded SIP002 user-id cap, wg URI host grammar check,
  profile-name traversal characters rejected.
- npm wrapper verifies the downloaded archive against its published
  `.sha256` (fail closed), extracts via argv-form `spawnSync` (no shell
  interpolation), retries downloads once, requires Node ≥14.14.
- CI gains a version-parity job (Cargo.toml == npm package.json ==
  RELEASE_TAG) and a pinned rust-toolchain (1.88 = CI toolchain).

### Fixed
- Ctrl+C hook failures are logged instead of silently leaving a scan
  running (scan + wizard paths); wizard prompts moved off tokio workers
  (`spawn_blocking`) and show a config summary before confirming.
- Inline phase-2 verifier invariant violations return failed verdicts
  instead of panicking a worker task; "every attempt failed" messages no
  longer claim probes never ran when they simply did not pass; ephemeral
  port errors carry their io::ErrorKind.
- dgst parser is line-exact (`SHA2-256= <hex>[ <filename>]`) so a long hex
  comment cannot satisfy the checksum; bundled range pools assert non-empty
  at test time; Windows token-size query validates ERROR_INSUFFICIENT_BUFFER
  before sizing its buffer.
- Stale docs/comments corrected (profiles persistence, spec/intent frontend
  reality notes, CHANGELOG newest-first order restored).

## [0.7.0] - 2026-08-24

### Added
- **Bilingual UI (English/Persian) with full RTL.** Header language toggle
  (persisted, `html[dir/lang]` applied pre-paint), Vazirmatn webfont,
  logical-property sweep, LTR-isolated data tokens. Pro panel fully
  translated (~120 keys).
- **Beginner mode upgrades:** candidates-to-test knob alongside find-target,
  copy → share-sheet → .txt export fallback chain, honest stop-overshoot
  hint ("a few extra working IPs may land after the target").
- **Pro mode additions:** ranges list-file import (server-grammar
  validated, bare IPs classified per mode), AmneziaWG noise editor over the
  pasted wgconf (plain INI or `awg://` base64 URI round-trip, Off/Light/
  Heavy presets, constraint validation per the 2026-08-23 research), and
  Skip-to-Phase-2 — cancels phase 1 mid-scan and verifies the banked
  candidates via `phase2_only`, with a low-yield suggestion badge.
- **WARP verify mode completes a full WireGuard session.** Verify probes
  now finish the cryptographic handshake under the user's keypair AND push
  an encrypted DNS query through the tunnel, passing only on a data reply —
  shape-only replies cannot tell a dummy-key handshake from a real one.
  Discovery stays shape-only; verified scans badge their results.
- **Client-side validator module** (`ui/src/lib/validators.ts`) mirroring
  the server grammar: inline field errors gate both scan start and profile
  save; pasted endpoint/CIDR lists normalize on blur (blank and duplicate
  lines dropped); the ranges importer classifies with the same rules.
- Results-table UX: tri-state `aria-sort` headers, 44 px touch targets,
  bulk-copy live region, skeleton rows, filtered/true-empty states, and a
  render cap for very large scans.
- Grammar fixture (`tests/fixtures/grammar-cases.json`) pinning
  CIDR/endpoint/SNI parsing for the server tests and the UI mirror.

### Fixed
- **UI phase-2 starts were rejected (422).** The form sent lowercase
  fragment presets (`off`) while the API contract is `Off`/`Light`/… —
  every UI-initiated phase-2 scan failed before it began. The form now maps
  to the wire form (saved profiles keep loading) and fragment errors route
  to the fragment field.
- Pasting a wgconf now auto-enables real-keypair verification (previously
  only the file-import path did), so verify-mode scans are never silently
  run with the dummy key.
- Mode flip no longer wipes restored port selections on hydration or
  cross-mode profile loads; each import button targets its own field;
  failed stop/cancel requests surface in the UI; ETAs humanize past 60 s.

- SSE `/api/events` no longer closes idle connections after replaying the
  previous run's terminal: a browser EventSource held open between scans used
  to reconnect-storm (connect -> replay -> close -> reconnect) and could miss
  the next run entirely. A replayed terminal is now context only; the stream
  ends on the next run's live terminal or an unrecoverable lag. Graceful
  shutdown additionally bounds its wait (5 s grace) so deliberately-open idle
  streams can never hang process exit.

- **Stale validation message.** "Fix the highlighted fields to continue."
  no longer lingers after the user corrects the field — the message clears
  live while typing and stays cleared after Next.
- **Forward tab clicks were silently swallowed** until validation passed.
  Tabs now navigate freely in both directions; validation errors paint on the
  target step when it is shown.
- **Mode switch kept the previous mode's default port** (e.g. 2408 carried
  into CDN mode). The wizard now shows an inline amber warning when a custom
  port differs from the mode default and never silently rewrites custom
  values; untouched defaults still auto-correct (443 ↔ 2408).
- **Rate stat showed "0/s" when idle.** The rate is now hidden whenever no
  scan is running and appears only during a live scan.
- **"URIs" download option was offered when nothing could be exported**
  (WARP mode without configs). The option is now disabled in that state.
- Heading hierarchy: "Generate WARP config (optional)" was an H4 under an H2
  (skipped H3); it is now an H3.

## [0.6.0] - 2026-08-22

### Added
- **Rebuilt browser UI in Svelte 5**, embedded via rust-embed (the vanilla
  single-file page is gone). Simple mode by default: one-tap scanning with a
  live progress bar, rate/ETA and top-endpoint cards. A Pro toggle reveals the
  full console: complete scan configuration with inline validation and
  field-level errors, profiles save/load/delete, phase-2 verification with an
  xray availability chip + download, WARP identity registration (license +
  overwrite consent) with wgconf export, sortable results table with per-row
  importable-URI copy and copy-all, custom CIDR/exclusion editors, ranges
  info, and a small-mode knob ("find up to N IPs").
- **Cloudflare port picker**: checkbox chips from verified catalogs — CDN =
  the six TLS ports from Cloudflare's network-ports documentation
  (443/2053/2083/2087/2096/8443); WARP = the four official WireGuard ports
  (2408/500/1701/4500) behind a collapsible 50-port community-verified
  extended list — plus custom-port entry with inline validation.
- Mobile/responsive pass: results table scrolls inside its card, ≥44px touch
  targets on coarse pointers, 16px inputs below 640px (no iOS zoom-jump),
  wrapping header, safe-area insets, scroll-jank-free background blooms.

### Changed
- SSE `/api/events` keeps idle connections open across scans: a replayed
  terminal from the previous run is context only, so browser tabs stop
  reconnect-storming while idle. Graceful shutdown bounds its wait (5 s) so
  deliberately-open streams can never hang process exit.
- Latency values use a dedicated green/amber/red ramp; brand orange now means
  brand/actions only. Fonts ship bundled (Inter + JetBrains Mono) — the UI
  makes zero CDN calls.

### Fixed
- Starting a scan no longer errors client-side with "Unexpected end of JSON
  input" (202-with-empty-body responses are handled).
- Idle EventSource connections closed-and-reconnected endlessly after
  replaying a stale terminal, which could also miss the next run's events.
- Copy affordances tell the truth: cards copy ip:port and say so; passing
  phase-2 rows offer the real importable URI via `/api/config/export`.

## [0.5.1] - 2026-08-21

### Changed
- **WARP working verdict now requires zero probe loss.** An endpoint appears
  in results only if every WireGuard probe answered (0% loss); endpoints with
  any probe loss are excluded entirely instead of being listed with a loss %.
  "Stop after N found" and latency-based ranking count zero-loss endpoints
  only (QA decision 2026-08-20, see ADR-002 update).
- SSE `/api/events` streams end after the run's terminal event instead of
  hanging open, so graceful shutdown completes while a UI tab is connected;
  clients that subscribe mid-finish now replay the terminal exactly once.
- `--cap` is enforced run-wide across phases 1+2 (was per-phase), and
  `phase2_only` runs count verification attempts in `summary.scanned`
  (previously reported 0).
- Removed the always-0.0 `loss_pct` field from verdicts (API, engine, UI
  table and CSV export).

### Added
- `serve --autostart=remove` unregisters the start-with-Windows entry without
  `--tray`; registration now happens only after a successful bind.

### Fixed
- WARP mode fails loudly on unparsable `--exclude` CIDRs instead of silently
  scanning excluded space.
- A panic unwinding through a scan can no longer leave the controller
  permanently busy ("a scan is already running").
- Closed the `/api/events` missed-terminal race, the concurrent-start race
  (racing POSTs get 409, no phantom `Failed` mid-scan), and the WARP
  registration overwrite-consent race.
- A corrupt persisted WARP server key falls back to the bundled constant
  instead of panicking every probe.
- Hostile tunneled responses can no longer force 64 MiB allocations per
  attempt (probe body cap) and over-cap socks responses fail explicitly
  instead of truncating silently.
- Windows secret files (`identity.json`, `profiles.json`, trial configs) are
  locked down to the owning user with a protected DACL.
- The GeoIP build cache verifies its SHA-256 sidecar before use and writes
  atomically; truncated caches re-download instead of persisting forever.
- `xray` download/export errors are sanitized like every other path; the
  Host allowlist is case-insensitive and rejects `::1` (server binds IPv4
  loopback only); explicit byte caps on license and export-config fields;
  wizard Ctrl+C detected by type; outbound fetches accept bracketed IPv6
  literals.

## [0.5.0] - 2026-08-18

### Added
- **In-process VLESS/Trojan verifier.** Phase-2 attempts whose protocol is
  plain VLESS or Trojan (TCP transport, TLS or plain, fragmentation off)
  are now verified in-process over rustls — no xray subprocess, no temp
  config, no ~50-200ms spawn cost. Everything else (WS transports, VMess,
  Shadowsocks, and every DPI-fragment preset) falls back to the xray
  subprocess as before. `Phase2Verdict.verifier` reports which path
  verified each row ("inline" | "xray").
- **Config export.** Any vless/trojan link from the phase-2 config can be
  re-rendered against a scanned endpoint: per-row Export in the UI,
  `POST /api/config/export`, and the `cf-scanner export-config` CLI
  subcommand. Export keeps the scheme and query params (SNI can be
  overridden) and rewrites host/port to the verified endpoint.
- **Multiple phase-2 probe URLs.** `--phase2-probe-urls` (UI: textarea)
  checks every URL over one keep-alive tunnel; all must return HTTP 200
  for the endpoint to count as working.
- **Windows tray** (`serve --tray`): tray menu starts/cancels CDN and WARP
  scans, opens the UI, and exits `serve` gracefully. `--autostart` (with
  `--tray`) registers a `CF-Scanner` entry under
  `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.
- **Offline builds.** `CFSCANNER_OFFLINE_BUILD=1` skips the GeoIP download
  and embeds a placeholder database; lookups degrade to `None` instead of
  failing the build.
- Frontend: “Add failed to exclusions” button, per-row Export buttons,
  probe-URLs textarea, and an exact “Stop after at least N found” label
  (the engine stops once found ≥ N; in-flight probes may add up to the
  concurrency setting more, all of them valid working endpoints).

### Changed
- Default probe concurrency 200 → 64 (kinder to the network and to
  Cloudflare; still saturates typical links).
- SOCKS5 HTTP client extracted into `src/socks.rs` and shared between
  phase-1 probing and the inline verifier; scan planning moved into
  `src/engine/plan.rs` (pure refactors, no behavior change).
- README gained a legal notice (Cloudflare ToS / impersonation warning,
  wgcf-style `okhttp/3.12.1` user agent).

### Fixed
- **Phase-2 probes through Cloudflare Worker (edgetunnel) configs never
  passed.** Two causes: (1) the default probe URL `https://cp.cloudflare.com/`
  cannot be proxied by a Worker — Cloudflare blocks outbound TCP sockets to
  its own IP ranges, so the tunnel hung after the vless header; the default
  is now `https://www.google.com/robots.txt`. (2) The worker tunnel closes
  the upstream without a TLS close_notify, which rustls reported as
  `UnexpectedEof`; the SOCKS5 HTTP client now treats that as the end of an
  HTTP/1.1 `Connection: close` body instead of discarding the delivered
  response. Verified end-to-end: a worker vless config now passes 4/4 and
  12/12 candidates.
- **xray binary download failed on GitHub release URLs.** The custom HTTP
  client could not follow GitHub's 302-to-CDN redirect; the download now
  uses reqwest with a redirect policy. Also trimmed a trailing newline from
  the pinned xray version that corrupted asset URLs, and the UI no longer
  shows a doubled "v" prefix next to the version.
- **Reset left stale rows in the table.** The reset handler cleared the
  data model but never marked the table dirty, so the DOM kept showing
  old rows while the stats read 0 (QA finding, fixed and verified).
- Stale live-progress line could reappear after cancel when a status poll
  in flight repainted progress over the terminal state.
- Test doubles (`FakeTransport`/`Scripted`) are now truly `#[cfg(test)]`
  -gated, matching their docs; merged `plans/` removed.

### Performance
- Phase-2 verification for plain vless/trojan configs drops from an xray
  spawn (~50-200ms) to a single in-process TLS round trip, and one xray
  spawn now serves all probe URLs instead of one per URL.

## [0.4.0] - 2026-08-16

Review-driven hardening from the
[finished-product review (2026-08-13)](docs/review/product-review-2026-08-13.md).
Changes merged by the `review/*` branches land here.

### Security
- Host-header allowlist + Origin/Sec-Fetch-Site checks close the
  DNS-rebinding/CSRF/SSRF surface of the unauthenticated localhost API.
- Phase-2 configs over the HTTP API accept URLs/URIs only; local file paths
  stay CLI-only.
- Profile responses mask WireGuard key material.
- Trial xray configs written 0600; stale `trial-*` dirs swept on startup.
- Trial config directories are removed on drop even when the attempt dies
  mid-flight (cancel, shutdown) — plaintext-credential configs never survive
  on disk.
- xray stderr is masked against the trial config's credentials (user ids,
  passwords, fronting SNI/Host) before it is logged or surfaced; error text
  is sanitized (URL userinfo/query stripped, lines capped).
- The WARP identity file is written 0600 (owner-only) atomically (temp +
  rename), so the private key is never world-readable, not even for a
  microsecond.
- List fields (ports, SNIs, exclusions, CIDRs) capped and deduped.

### Performance
- Bounded probe fan-out: a worker pool drains the plan instead of spawning a
  task per (host, port); `Preset::Full` can no longer OOM the process.

### Reliability
- xray lifecycle: graceful shutdown reaps children, fast corrupt-binary
  detection, stderr surfaced (redacted), single pre-flight download.
- Cancelling a scan now stops phase-2 verification too: one cancel signal is
  shared across phases, so a cancel fired during phase 1 (or in the gap
  before phase 2) halts tunnel probes immediately instead of leaving them
  running.
- The event stream re-syncs against the results store: a consumer that fell
  behind (dropped events) is re-served the verdicts it missed at end of run,
  deduplicated by endpoint, so results are never permanently lost.
- With phase 2 enabled, the found-count summary reflects verified working
  endpoints — candidates that failed verification no longer count as found.
- Zero-candidate scans no longer destroy results; run failures surface
  instead of hanging the UI.
- Bundled xray is size-checked so a corrupt or placeholder binary fails fast
  with a clear error instead of a confusing run failure.

### Changed
- WARP input validation: `--preset` and `--custom-cidrs` are rejected for
  WARP scans (both are CDN-only concepts — WARP takes `--count` +
  `--warp-endpoints`); duplicate endpoints and ports are deduped so no
  endpoint is probed twice.
- Dense IPv4 blocks (/24 and tighter) sample only real hosts — network and
  broadcast addresses are skipped.
- The WARP server public key is persisted at registration and preferred over
  the bundled constant, so probes keep working if Cloudflare rotates it.
- VMess `alterId` and AEAD `security` settings pass through to the xray
  config; `reality` security is rejected up front with a clear error (the
  builder cannot emit a working reality outbound).
- Phase-2 fragment wiring is gated: the `dialerProxy` chain is only attached
  when a fragment outbound actually exists, so a custom preset with no
  values can no longer produce a config xray refuses to run.

### UI
- Scan-state machine rework: real "Cancelled" state, start/reset guards,
  live-region + progressbar accessibility fixes, light-theme contrast pass,
  SSE reconnect/recovery.

### Docs
- spec.md flipped to APPROVED; stack/structure/testing corrections.
- README customer quickstart; docs index + QA runbook; task-tracker
  reconciliation.

### Added
- Property-test suites (proptest) for the config/URI parsers, wgconf, and
  the chunked-transfer decoder; `decode_chunked` now has bounds tests
  (huge sizes, truncation, malformed streams).
- CLI: WARP scans without `--count` now default to the full bundled pool;
  `--phase2-only` and `--cap 0` are rejected up front; `--phase2-custom`
  requires `--phase2-configs` + a custom fragment preset.
- API: `/api/warp/register` is rate-limited (1 per 60 s) and refuses to
  replace an existing identity unless `overwrite:true` is sent — the UI
  retries once with consent on a 409.
- API: custom CIDRs/endpoints that are non-routable (loopback, link-local,
  unspecified, RFC1918, ULA) are rejected with a 400; the CLI stays
  unrestricted.
- WARP scans driven over the API use the canonical WARP port set when the
  caller left the default port.

### Changed
- CLI: wizard prose moved to stderr (the wgconf export stays on stdout);
  Ctrl+C during the wizard exits 0; a closed output pipe cancels the scan
  instead of panicking; `shutdown_signal` no longer parks forever.
- Server: an SSE consumer that falls irrecoverably behind is disconnected
  instead of being replayed a stale run; a client connecting after a run
  ended gets exactly one terminal event replayed (tagged by run epoch).
- UI: toast auto-dismiss works under reduced motion; the progress title is
  throttled; IPv6 sorts correctly; a new run's generation guard stops
  replayed terminal events from older runs; loading a profile no longer
  clobbers user-configured ports; results sort by latency by default with
  missing values last; reconnect refreshes progress.
- CI: the release workflow attests artifacts (`id-token`/`attestations`
  permissions), its gate runs test + clippy + fmt + audit and blocks the
  host job; checks run on Windows too; a parity job fails fast if the
  pinned xray release disappears; the MSI ships the MIT license; rust-cache
  re-added.
- Test fixtures no longer carry real credentials (UUIDs/private keys
  replaced with inert zeroed values).

## [0.3.0] - 2026-08-13

### Added
- `GET /api/status` endpoint returning server version and scan state.
- Frontend loads scan results on page refresh via `/api/results`.
- Toast notification system for user feedback (copy, download, profile
  save/delete).
- Download dropdown with TXT/CSV/JSON formats and timestamped filenames.
- Empty results table shows a centered CTA instead of a blank row.
- Status card shows ETA and "X of Y scanned" during scan.
- Retry button on scan failure.
- Skip-to-content link and screen-reader-only live regions for result
  count and sort announcements.
- Keyboard-operable sort headers (Enter/Space).

### Changed
- Embedded frontend typography: rem-based sizing, tabular-nums on
  numeric columns, 3-state theme toggle (Auto/Light/Dark), spacing
  token system, compact 48px header with backdrop blur and GitHub link.
- Form improvements: inline help text, Ctrl+Enter shortcut, disabled
  field explanations, field error styling.
- Data table: right-align numeric columns, default sort by latency,
  sticky first column support, tabular-nums on mono cells.
- Progress bar: 8px height, ease-out transition, auto-scroll on
  completion.
- Clipboard copy: icon swap to checkmark on success, aria-live toast
  on success/failure.
- Reset button confirms before clearing results when data exists.
- Download filenames use `cf-scanner-{mode}-{ISO8601}.{ext}` pattern.
- Profile storage sanitizes WarpConfig to strip `generate_config` and
  `warp_plus_license` before persisting.
- API error responses now return structured JSON instead of plain text.

### Fixed
- `ranges` endpoint no longer includes `bundled` field (unused by frontend).
- Theme button aria-label mismatch (removed redundant label).
- `prefers-reduced-motion` now selectively disables animations instead of
  blanket-removing all transitions.
- `forced-colors` support for progress bars, segmented controls, and
  focus outlines.

## [0.2.0] - 2026-08-13

### Added
- IPv6 candidate ranges in phase 1: official Cloudflare v6 list bundled
  (`data/cf-ranges-v6.txt`), `--ipv6` CLI flags, `ScanConfig.include_v6`
  toggle, IPv6 verdicts (wire-compatible `IpAddr`), v6 exclusions/sampling.
- Background ranges refresh (24h, non-blocking, failure keeps last-good data)
  and `last_updated` (RFC3339 UTC) on `GET /api/ranges`.
- In-memory scan profiles API (`GET/PUT/DELETE /api/profiles[/{name}]`,
  session-lifetime, validated configs, no persistence).
- UI: dark mode (system + manual toggle), results density toggle, latency
  histogram, fragment preset editor (custom fields), client-side CSV/JSON
  results export, WARP wgconf import (paste + file picker), profiles panel,
  ranges last-updated display, IPv6 checkbox.
- Development + release process docs (`docs/development.md`,
  `docs/release-process.md`, ADR-007) so future developers and agents follow
  one local build/test flow, versioning contract, and publishing pipeline.
- Post-v0.1.0 roadmap in `tasks/plan.md` (Phase 7 candidate tasks).
- `cargo audit` dependency scan as a mandatory CI check (was local-only).

### Changed
- Release archives now carry only the target platform's xray binary; the
  foreign 0-byte placeholder is dropped at build time.
- CI checks updated to `actions/checkout@v6` (Node 20 deprecation).
- `ScanTarget::Count` is capped at 100 000 (an unauthenticated scan request
  could otherwise allocate gigabytes and abort the process).

### Fixed
- `GET /api/profiles/{name}` now exists; the UI's Load button previously
  404'd because the route only handled PUT/DELETE.
- A panicking scan run no longer permanently bricks the controller: the
  busy flag and cancel slot are reset via a RAII guard, and mutex poisoning
  is tolerated everywhere.
- IPv6 ranges refresh is atomic (temp file + rename) with a last-updated
  header, matching the v4 refresh (torn reads could fail concurrent scans).
- IPv6 entries are dropped from the IPv4 refresh feed (a v4-only scan could
  otherwise silently scan v6 hosts); v6 `/0` custom ranges are rejected with
  a clear error instead of producing off-by-one exclusion math.
- CSV export neutralizes spreadsheet formula injection (`=`, `+`, `-`, `@`
  lead-ins); copied/saved endpoints bracket IPv6 addresses (`[::1]:443`).

## [0.1.0] - 2026-08-13

### Added
- Project skeleton: CLI entry (serve/scan/ranges), CI checks workflow,
  bundled Cloudflare IPv4 ranges + WARP endpoint pools + pinned xray version.
- API contract types (`ScanConfig`, `StopCondition`, `Verdict`, `ScanEvent`)
  with input validation.
- Ranges engine: CIDR parsing/normalization, exclusion subtraction, preset
  and count sampling plans, `ranges refresh` via verified HTTPS fetch.
- Phase-1 probe transport: injectable TCP+TLS latency probe (no cert
  verification by design; real validation lands with phase-2).
- Scan controller: stop conditions (N found / hard cap / run-until),
  concurrency-limited fan-out, SSE-style event stream (progress/results/
  finished), latency-sorted results store, cancellable runs, last-scan-only
  semantics. Phase-2/WARP modes explicitly rejected until Tasks 11/12.
- Local HTTP server (axum) on 127.0.0.1: scan start, SSE event stream,
  results+summary, cancel, reset, ranges, embedded placeholder UI.
- Phase-2 config parsers: `vless://`/`trojan://`/`vmess://`/`ss://` URIs,
  subscription URLs, and Xray JSON → normalized outbound spec.
- Phase-2 verification engine: spawns the official xray binary
  (`xray run -c config.json`, local socks inbound), DPI-bypass fragmentation
  (light/medium/heavy/custom presets via freedom outbound +
  `sockopt.dialerProxy`), per-IP verdicts with SNI/fragment details.
- WARP mode engine: UDP endpoint discovery with real WireGuard handshake
  probes (boringtun), optional wgconf verification, opt-in client registration
  via Cloudflare's API + wgconf export.
- GeoIP: db-ip.com Lite country MMDB embedded at build time; country and
  datacenter (colo) shown in results and sortable in the UI (CC BY 4.0).
- Release pipeline: cargo-dist with msi/shell/powershell installers, 5-target
  matrix, and the xray binary bundled into every archive (checksum-verified at
  build time).
- README, docs/decisions ADRs (xray bundling, boringtun, db-ip, fragment
  chain, single-binary contract, no-history/no-telemetry).

### Changed
- `stop.cap` may now be smaller than `stop.found` (the cap wins first);
  previously such configs were rejected as invalid.
- `custom_cidrs` now REPLACE the bundled ranges (was: merged in addition);
  exclusions still apply to custom ranges.

[0.4.0]: https://github.com/QMahyar/cf-scanner/releases/tag/v0.4.0
[0.3.0]: https://github.com/QMahyar/cf-scanner/releases/tag/v0.3.0
[0.2.0]: https://github.com/QMahyar/cf-scanner/releases/tag/v0.2.0
[0.1.0]: https://github.com/QMahyar/cf-scanner/releases/tag/v0.1.0
