# Spec: best-in-class scanner (WARP + CDN, pure CLI)

Status: PROPOSED (synthesis of wayfinder map `docs/wayfinder/best-in-class/`, tickets 01–07 resolved 2026-09-18; closing ticket 08 locks this as the destination — execution is follow-up work, no code lands here)
Date: 2026-09-18
Source tickets: `docs/wayfinder/best-in-class/tickets/01`–`07` (## Answer + ## Resolution are decided — this spec does not re-litigate them)
Constraints: `CONTEXT.md` glossary (`Working` binary), `AGENTS.md` v0.8.0 invariants + boundaries (USER-GATED releases), `docs/spec.md` §10 (opt-in-only defaults).

> Note: AGENTS.md asks for the `rust-engineering` skill before Rust work.
> It is absent in this session (not in the available-skill list); the closest
> available skill (`rust-async`: bounded channels, `select!` cancel races, no
> lock across `.await`) was loaded instead. All insertion points below were
> verified by direct reads of the cited files.

## 0. Non-goals (reaffirmed, not ranked)

Pure CLI only (ADR-013): no GUI/desktop/mobile/Docker. No history/telemetry/
phone-home (ADR-006): no update banner, no `latest` resolution, no `VERSION`
polling. No committed binaries, no checksum-less downloads (`.dgst` + caps
stand). No default-on speed tests (intent ban; `--speed-test` stays opt-in).
CDN ranges stay official-only (`data/cf-ranges.txt` == official 15/15,
verified 2026-09-18); SenPai's 613 ASN extras are reachable only via explicit
`--custom-cidrs`.

## 1. P0 — first execution slice (ordered, each independently shippable)

Every item: opt-in or no-behavior-change, S effort (≤5 files), additive only.

### P0-1. WARP pool 8 → 15 /24s (data-only)
- **What:** append the 7 probe-verified missing /24s to `data/warp-pools.txt`:
  `8.6.112.0/24, 8.34.70.0/24, 8.34.146.0/24, 8.35.211.0/24, 8.39.125.0/24, 8.39.204.0/24, 8.39.214.0/24`.
- **Why:** BPB `main.go:112-114` (`generateEndpoints`) and warpscout `pools.go`
  (`poolsV4`, 14 /24s) both ship them; 6vBPB/7vwarpscout genuinely missing (§05
  Answer). All 7 trace to SenPai ASN space AND are probe-verified WARP space —
  admissible as pool entries, NOT as CDN ranges. `162.159.193.0/24` stays
  (warpscout dropped it; ours traces to official `162.158.0.0/15`).
- **Insertion:** `data/warp-pools.txt` (8→15 lines); update `8*256` test
  expectations at `src/warp.rs:478` + `src/engine/warp.rs:494` as a consequence.
- **Effort:** S (1 data file + 2 test constants).
- **Contract:** none. **Default:** broader pool only; sampling math unchanged.

### P0-2. Budget-split timeouts for TCP/TLS (always-on, no flag)
- **What:** wrap connect/handshake in per-step budgets reusing `step_budgets`
  (`src/probe.rs:218-223`, today HTTP-only at `:231-277`): TCP connect ≤¼,
  TLS ≤½ of remainder, outer `timeout_ms` stays the ceiling.
- **Why:** SenPai `prober.go:269-275`; black-holes fail faster with identical
  ceilings and verdicts — strict improvement, owned by ticket 03 (§03:72-81),
  ticket 04 defers to it (§04 row 1).
- **Insertion:** `src/probe.rs:111-155` (`TlsTransport::probe`, outer timeout
  `:133`) + `src/probe.rs:160-194` (`TcpTransport::probe`, outer timeout
  `:171`); `reason()` strings (`:31-40`) unchanged.
- **Effort:** S (1 file + tests). **Contract:** none. **Default:** none in
  outcomes (only faster failures) — the single sanctioned always-on change.

### P0-3. SOCKS `ServerName` repair for IP dials
- **What:** one shared host→`ServerName` helper in `src/socks.rs` (explicit
  `IpAddr` parse fallback + bracket strip, mirroring
  `src/configs/mod.rs:293-299` / `src/configs/uri.rs:265-266`); call it at
  `get_via_socks_inner` (`src/socks.rs:389-390`), `timed_download_via_socks_inner`
  (`:298-299`), and the inner handshake (`src/inline_verify.rs:229-237`).
- **Why:** SenPai `runner.go:157-159,775-802` (`verifyPeerCertByName`); IP-literal
  dials with SNI certs fail without it. The `socks5h` half needs nothing:
  `socks5_connect` (`src/socks.rs:412-460`) already sends ATYP-domain (`:431-438`).
- **Effort:** S (2–3 files). **Contract:** none. **Default:** none (repairs
  failures into successes only on previously-failing dials).

### P0-4. Share-URL hardening: missing-`?` recovery + truncated-JWT shape check
- **What:** (a) at `parse_sip002` head (`src/configs/uri.rs:255-329`),
  single-pass reattach of trailing `&`/`=` segments as query when no `?` is
  present (SenPai `parser.go:417-537`); (b) shape-only credential check in
  `parse_uri`/`finish_spec` (`src/configs/uri.rs:18-33`,
  `src/configs/mod.rs:200-262`): segment-count/base64url-decodability →
  actionable error pre-spawn. No signature checks, no new dependency.
- **Why:** malformed share links today die downstream (spawn/inline-UUID) or
  silently drop params into defaults (`Url::parse` at `uri.rs:256`).
- **Effort:** S (2 files + tests). **Contract:** none (error strings only;
  errors surface via existing `ignored+errors` /
  `src/engine/phase2.rs:330-333` skip-warn). **Default:** none.
- (`&`-in-path auto-join stays dropped: `QUERY_VALUE_ENCODE_SET` already
  includes `&` (`uri.rs:42-57`) so well-formed links are safe; auto-join is
  ambiguous. `worers.dev` auto-correct stays dropped — target mutation;
  warn-only candidate stays P1-optional, §04 rows 8b/8c.)

### P0-5. WARP DPI noise core: junk-send discovery + H/S/I1 honor in verify
- **What:** (a) AWG junk-send (`-jc/-jmin/-jmax`, `-gen-junk` values) in the
  discovery probe: junk = plain UDP datagrams *around* the existing
  `Tunn::format_handshake_initiation` (`src/warp.rs:258-264`) via
  `SocketCache::get_or_bind` (`src/warp.rs:108-134`) + `rand_core 0.6.4`
  (`Cargo.toml:26`); junk sends go through `send_bounded` (`src/warp.rs:230-236`)
  so the per-call timeout rule holds. (b) Honor parsed `H1-H4`/`S1-S2` +
  I1-generator first packet in the verify-with-wgconf path
  (`src/warp.rs:143-191`): `AmneziaParams` is parsed/rendered
  (`src/wgconf.rs:22-33,259-292`) but `WgVerifyTransport` ignores it
  (`src/warp.rs:143-160`), so verify against an AWG gateway with nonzero
  params fails today — correctness, not just evasion.
- **Why:** warpscout 4-transport audit (`warp.go:149-183`); junk-as-separate-
  datagrams is the only noise safe against the plain-WG CF edge (server drops
  unknown packets), while H/S/I1 *mutations of the Init* require an
  AWG-speaking server — hence discovery never mutates the Init, verify honors
  params (§01 ranks 1–2).
- **Insertion:** `src/warp.rs` + `WarpConfig` fields; params travel
  `WarpConfig` → transport constructor, so per-worker channels
  (`src/engine/warp.rs:84-92`), producer backpressure (`:108-115`), and
  `select!`+cancel races (`:132-159`) are untouched.
- **Effort:** S (junk) + S/M (verify honor). **Contract:** new `WarpConfig`
  fields need `#[serde(default)]` under `deny_unknown_fields`
  (`src/api/types.rs:176-177`). **Default:** none — junk params default
  off/zero; loss accounting (`src/engine/warp.rs:139-180`) untouched, junk
  sends are not probes, `Working` stays open + zero loss per glossary.
- **IPv6 scope:** IPv4 pool sampling only (inherits `src/warp.rs:201-205`,
  `src/engine/warp.rs:241` IPv4-only scope; see §4).

### P0-6. Torn-down signal as export-only `fail_reason` (opt-in, WARP-only)
- **What:** classify torn (handshake OK, dies mid-stream: trailing run ≥3
  unanswered + confirm burst, min burst 5) as a stored row with
  `fail_reason="torn_down"`, `latency_ms: None`, `loss_pct` set. Active only
  when `--warp-probes >= 4` (unobservable at the default 3). Torn rows: appear
  in csv/json + end-of-scan diagnostic flush; never count toward
  found/stop, never emit live `Result`-as-working, never eligible for
  best/conf/bundles. Share the `torn_down` wording with phase-2 and wgconf
  verify errors (wording only, no structural change there).
- **Why:** warpscout `tunnel.go:354-367,457-467` + double-burst `197-207`,
  `working = ok && durable`, torn never wins (`main.go:421-439`) — without
  their ternary-state cost: `latency.is_some() ⟺ working` invariant
  (`driver.rs:60-77` `record_and_batch`, `mod.rs:228-234`,
  `cli_wizard.rs:297`, `export.rs:27`) stays intact, zero contract change,
  bundles already key off `phase2.passed` (`export.rs:247`) (§02).
- **Insertion:** `src/engine/warp.rs:139-187` (store a new row kind where lossy
  endpoints are dropped today at `:180`); counting guards so torn rows skip
  `found`/stop; `diagnostic_line` (`src/export.rs:21`) already renders
  `fail_reason`.
- **Effort:** S (1–2 files + tests). **Contract:** none (fields + columns
  exist). **Default:** none (dormant unless probes raised).
- **Speedtest policy:** torn rows never enter the speed-test shortlist
  (`latency None` ⇒ not passing; `src/engine/speed.rs:67-100` index collects
  phase-2 passes only) — no serial-vs-sample change needed (§4).

### P0-7. Adaptive UX framing: `--adaptive-retries`, `--network-profile`, wizard strings
- **What:** (a) opt-in `scan --mode warp --adaptive-retries`: engine-side
  pre-flight of exactly 100 handshake probes over the bundled pool plan,
  each bounded by `--timeout-ms`, Ctrl+C-abortable, zero verdicts; ladder
  `loss > 10%` or `p50 > 800` → 5, `loss > 25%` or `jitter > 1500` → 7
  (jitter = p90−p50), never above max 10, never lowering an explicit
  `--warp-probes` (explicit wins, pre-flight skipped with stderr note);
  stderr-only output + reusable re-run line, stdout NDJSON unchanged.
  (b) `--network-profile blocked|slow` (unset = today): CDN blocked →
  `timeout_ms 5000` + `idle-hold 2000`; slow → `timeout_ms 8000`, concurrency
  halved; WARP blocked → probes 5, slow → probes 3 + timeout 8000; explicit
  flags always win. (c) Wizard: blocked-vs-slow Select after mode (recap
  `profile blocked`), fragment prompt reframed ("fully blocked (heavy) or
  just slow (light)?", Medium + Custom kept), plus the four §06 strings:
  endpoint prompt gains `(IPv6 as [addr]:port)`; client labels `v2ray format
  (v2rayN / v2rayNG / NekoBox clipboard JSON)` and
  `sing-box / clash / Shadowrocket / Quantumult`; stop prompt gains
  `Stop after N working endpoints (unreachable = excluded, slow = kept —
  slowness is filtered by --min-speed, not here)`.
- **Why:** BPB `network.go:71-194` (100-sample 3→5→7 pre-test + noise UX worth
  stealing, engine not worth copying); warpscout stdout=machine/stderr=human
  contract; Ptech dual-format/bind UX reference (§03, §06).
- **Insertion:** `src/api/types.rs` (flat root `adaptive_retries: bool` +
  profile field — root stays non-strict per `:198-202`, plain
  `#[serde(default)]`); `src/cli.rs` (flags); `src/cli_wizard.rs:54,447`
  (stop prompts), `:339` (best-endpoint note), `:695` (recap);
  engine helper on `ScanController`.
- **Effort:** S per piece (≤3 files each; wizard strings S, 1 file + recap
  tests at `cli_wizard.rs:1269-1324`). **Contract:** additive root fields
  only. **Default:** none (all opt-in; pre-flight never default-on).

### P0-8. `warp-config export --bind-best` + `Reserved` passthrough
- **What:** (a) `--bind-best [--out FILE]` stamps `Endpoint = <lowest-latency
  working result>` from the in-memory last scan (fallback `--endpoint` when
  given; error when empty); file/`-` body unchanged, human note on stderr.
  (b) additive `Reserved` parse/render passthrough on `WgConfig`
  (`src/wgconf.rs:13-33`, `parse_awg_uri :88-127`, render `:259-292`):
  default-off, round-trips, for V2rayNG import parity (real gap: no `Reserved`
  field today, §06 Answer).
- **Why:** Ptech `install.sh:193-248` (`sed Endpoint=`) auto-inject + Ptech
  Reserved-for-V2rayNG note, in CLI form; wizard already does this
  interactively (`src/cli_wizard.rs:330-360`) — the gap is non-interactive.
- **Insertion:** `src/cli.rs:147-169` (`--endpoint` area), `src/main.rs:124`
  (export path), `src/wgconf.rs`. **Effort:** S. **Contract:** none
  (CLI-local + additive struct field with default). **Default:** none.

## 2. P1 — second slice (ordered; needs P0 or design first)

### P1-1. `tune` subcommand (`tune fragment` / `tune junk` / `tune sni`)
- **What:** `cf-scanner tune junk [--candidates 50 --need-pct 30]`,
  `tune sni [...]`, `tune fragment --config <uri> [--need 3]` (fragment:
  light→medium→heavy over a small fixed candidate subset through xray, stop
  at first preset verifying `need` endpoints). Each walks a bounded candidate
  list, prints per-step stderr (`try junk=64: 12/50 open (24%)…`) then a
  reusable `use: cf-scanner scan …` command to stdout; total cost printed up
  front; every step checks stop/cancel; never logs configs/keys.
- **Why:** warpscout `find-junk`/`find-sni` threshold loops that print reusable
  commands — steal the UX pattern only; no persistence beyond retry-last
  (ADR-006 holds) (§01 rank 4, §03 Answer-2/5).
- **Depends:** P0-5 (junk knobs must exist; junk/sni tuners without engine
  knobs are dropped, not stubbed). **Insertion:** new `tune` subcommand next
  to `ranges`/`warp-config` style (`src/cli.rs`, `src/main.rs` dispatch,
  engine helpers reusing `probe_once(ShapeOnly)` / `verify_phase`).
- **Effort:** M (3–5 files). **Contract:** none new (reuses P0-5 fields;
  candidate-list flags are CLI-local). **Default:** none (separate subcommand).

### P1-2. Phase-2 tier fallback ladder (engine-level)
- **What:** in `verify_phase` (`src/engine/phase2.rs:21-62`): tier list
  `[user probe_urls] → [public trace + data-path]`; advance only when the
  previous tier yields zero passes; stop at first tier with ≥1 pass. `TunnelProbe`
  (`src/verify.rs:37-48`) stays single-shot (injectable/offline tests).
  Bound cost via existing `cap`/`stop_found`/`passed`-dedup (`:73-74,106-126`)
  + `select!` cancel (`:127-138`).
- **Why:** SenPai `runner.go:344-406` domain→…→data-path ladder; in-probe
  ladder and a distinct "tunnel-path" step stay dropped (our tunnel IS the
  transport; today ALL URLs must 200 over ONE tunnel,
  `src/verify.rs:253-271` `all_ok`) (§04 row 6).
- **Effort:** M (`src/engine/phase2.rs` + `src/api/types.rs` if tier knobs are
  added — then `#[serde(default)]` under `deny_unknown_fields` `:131-132`).
  **Contract:** additive-optional. **Default:** none (ladder only advances on
  zero-pass tiers; single-tier configs behave as today).

### P1-3. Opt-in SNI rotation (phase-1)
- **What:** SNI list param on `TlsTransport::new` (`src/probe.rs:80-93`) /
  `HttpTransport::with_shared` (`:196-215`) via `transport_for` (`:68-78`);
  new `ScanConfig` root field (plain `#[serde(default)]`, default = today's
  single `PROBE_SNI`, `src/probe.rs:17`). **Rotation policy (decided here):
  rotate per probe call by shared atomic counter** — strict round-robin
  sequential, spread under concurrency, no extra RNG, test-friendly
  (shipped as counter-based, not literal per-worker pinning: task→worker
  assignment already races, so pinning would be unobservable, and it would
  break the injectable-transport seam). Never 5× dials per IP (SenPai
  `prober.go:20-26,182-205` retry-all-5 stays dropped as cost).
- **Why:** SenPai 5-host rotation without its per-IP dial multiplication;
  phase-2 SNI *variants* (`src/api/types.rs:136`,
  `src/engine/phase2.rs:34-38`, `src/xray.rs:53-59`) are not the same thing
  (§04 row 2).
- **Effort:** S/M (2–3 files). **Contract:** additive root field.
  **Default:** none (single-SNI default).

### P1-4. Opt-in `--warp-port-gate` (fail-fast port narrowing)
- **What:** flag `--warp-port-gate` (name decided here): in
  `ScanController::run_warp` (`src/engine/warp.rs:27`), between transport
  construction (`:30-46`) and `warp_groups` (`:50`), a `port_gate()` helper
  samples 12 addrs from `bundled_pool().excluding(&excluded)` (same exclusion
  path as `warp_groups:227-234`), probing via the already-built transport
  (preserves per-controller `SocketCache`, `select!`+`cancelled()` race, no
  lock across await) × primary `[2408,500,1701,4500]`; only on TOTAL failure
  escalate to the 50-port extended list; total failure returns an empty
  summary with a stderr note (warpscout's abort), never an error. Skip gate
  when user passed explicit `--ports`/`--warp-endpoints`.
- **Why:** warpscout `discovery.go:103-161` (`sampleAddrs` 12 ×
  `primaryWarpPorts`, 50-port escalation, zero-open abort); BPB's 54-port
  list == same 4 primary + same 50 extended. Our `DEFAULT_WARP_PORTS`
  (`src/api/limits.rs:4`, 7 ports) already spans primary + 3 extended, so the
  value is fail-fast + narrowing, not coverage (§05).
- **Effort:** M (`src/warp.rs` constants + gate helper reusing
  `probe_once(ShapeOnly)`; `src/engine/warp.rs` call site; `src/api/types.rs`
  + `src/cli.rs`). **Contract:** new `WarpConfig` flag with `#[serde(default)]`
  (keeps `deny_unknown_fields` + root forward-compat). **Default:** none
  (strictly opt-in).

### P1-5. Speed-test burst fallback (behind `--speed-test` only)
- **What:** on full-download stall/timeout in `measure_endpoint`
  (`src/engine/speed.rs:140-145`, `timed_download_via_socks`
  `src/socks.rs:255-311`), fall back to N parallel small burst fetches (8×16 KB
  analogue) and record a lower-bound MB/s instead of erroring. Keep 8 MiB/30 s
  defaults (`SPEED_TEST_BYTES/TIMEOUT/CONCURRENCY/URL`, `:17-24`), reuse the
  `SPEED_TEST_CONCURRENCY` bound + `SpeedTester`/`TunnelOpener` seams (tests
  stay offline), cancel-inside-cleanup (`:230-263`).
- **Why:** SenPai `runner.go:727-766` parallel-burst throughput fallback; the
  128 KiB-minimum-sample-before-verdict for phase-2 stays dropped (slows every
  candidate; short-connection DPI kills are idle-hold's job, §04 rows 4/7).
- **Effort:** M (2 files). **Contract:** none. **Default:** none (behind
  opt-in `--speed-test`; `--min-speed` semantics unchanged).

### P1-6. Opt-in `--export-live FILE` + `--show-link` to stderr
- **What:** (a) `--export-live FILE`: append + flush per `ScanEvent::Result`
  (SenPai `output.go:36-42` crash-safe JSONL analogue; rows identical to NDJSON
  stdout shape), fsync on finish; conflicts with `--export` (which keeps atomic
  end-of-scan semantics via `atomic_write_file`, `src/export.rs:823`).
  (b) opt-in `--show-link` on `warp-config generate|export`: new pure renderer
  `render_awg_uri(&WgConfig)` (inverse of `parse_awg_uri`,
  `src/wgconf.rs:88-127`); link goes to **stderr** (human, QR/copy-paste),
  stdout keeps exactly one artifact (conf body) so `> out.conf` keeps working.
  Plus the `--export -` bundle rule (decided here): bundle-after-final-summary
  on stdout, documented as "not NDJSON-parseable when mixed; prefer a file".
- **Why:** Ptech dual print without breaking machine stdout; SenPai live
  writer without changing atomic `--export`; warpscout stdout=machine/
  stderr=human contract already satisfied — hold the line with a test per new
  output (§06 sketches B–D, §07 row 8).
- **Effort:** S/M (3–4 files). **Contract:** none (CLI/export-local).
  **Default:** none (both opt-in; default stays single-artifact + atomic export).

### P1-7. Explicit-only `self-update` (design-gated follow-up, not a proposal)
- **What (sketch input from §07, for a future design ticket):** explicit
  user-invoked `cf-scanner self-update [--tag vX.Y.Z] [--check]` only — never
  automatic, never a banner (ADR-006); no `latest` (default target = release
  tag matching the binary's own `CARGO_PKG_VERSION`); verify against published
  `.sha256` with `verifyChecksum`/`dgst.rs` strictness; reuse
  `ranges::HTTP_CLIENT` redirect guard + call-site timeout; Windows
  rename-and-replace dance; MSI installs refuse/defer; `--check` prints
  current-vs-target and exits. Platform matrix + npm-wrapper interplay are the
  design ticket's call. USER-GATED like all releases.
- **Effort:** M when approved (new subcommand + platform shims).
  **Contract:** none (no scan-config surface). **Default:** none.

## 3. Explicitly rejected (do not build; rationale + what stands instead)

| # | Rejected | Instead (stands) |
|---|---|---|
| R1 | QUIC-Initial-as-I1 for CF discovery (§01 rank 3) | Plain-WG Init + shape-only open (`src/warp.rs:405-411`, 92B/64B); CF edge is plain WG, disguised I1 breaks classification |
| R2 | MASQUE / MASQUE-H2 this cycle (§01 rank 5) — **crate choice CLOSED**: no quinn/h3 dep; MASQUE pools (`masque.go:56-87`, QUIC `162.159.198.1-2`, H2 `/24`s + v6) stay out of `warp-pools.txt` | Reopen only if UDP is fully blocked (new ticket, new 차단 evidence) |
| R3 | WARP-in-WARP nesting (§01 rank 6; `nest.go:193-260`, netstack + MTU−60) | Needs live session during scan; breaks injectable-transport tests + `SocketCache` ownership; niche for an endpoint finder |
| R4 | Ternary torn state / default-on torn / raised default probes (§02 Q1–Q3 alts) | `fail_reason="torn_down"` export-only opt-in (P0-6); zero-loss stays the WARP rule |
| R5 | Default-on adaptive pre-flight; `--tune-*` scan flags (§03 alts) | Opt-in `--adaptive-retries`; `tune` subcommand (P1-1); `scan` surface stays clean |
| R6 | Always-on-adjacent gating of budget-split behind a flag (§03 Q4 alt) | Always-on, no flag (P0-2) — the one exception, outcomes unchanged |
| R7 | Phase-1 WS-upgrade gate (§04 row 3) | Phase-2 end-to-end WS coverage stands (`src/verify.rs:499-504`, `src/xray.rs:68-78`) |
| R8 | Phase-2 idle-hold extension (§04 row 4) | Shipped `--idle-hold-ms` as-is (`src/probe.rs:135-147,173-186,283-295`); mid-verify RST already fails the candidate |
| R9 | Retry-all-5-SNIs-per-IP; in-probe phase-2 ladder + distinct tunnel-path step; 128 KiB min-sample verify gate (§04 rows 2/6/7 alts) | Worker-index rotation (P1-3); engine tier ladder (P1-2); burst fallback behind speed-test only (P1-5) |
| R10 | `&`-in-path auto-join; `worers.dev` auto-correct; strict JWT validation (§04 rows 8b–8d alts) | Encoder guarantee stands; warn-only typo candidate stays optional; shape-only check (P0-4) |
| R11 | SenPai 613 ASN extras into `data/cf-ranges.txt`; MASQUE pools into WARP pool (§05) | Official-only CDN boundary; explicit `--custom-cidrs`; pool +7 only (P0-1) |
| R12 | Default-on port-gate; gate covering explicit `--ports`/`--warp-endpoints` (§05 alt) | Opt-in `--warp-port-gate` with warpscout skip conditions (P1-4) |
| R13 | Dual print to stdout; `--bind-best` writing stdout; live export replacing atomic `--export` (§06 alts) | stderr link (P1-6); file/`-` body unchanged (P0-8); conflicting opt-in live flag (P1-6) |
| R14 | UPX-on-Linux; Docker; checksum-less `install.sh`; AUR; Go-GC knobs (`GOMEMLIMIT`/`BatchSize`/`SetGCPercent`); self-update-by-`VERSION`; update banner; SenPai reusable-workflow split (§07 rows 2–7,9) | dist + pinned `xray-version.txt` + `.dgst` + version-parity CI stand (stronger: tag-derived, no hardcoded `v1.0.0` edit-per-release); Rust footprint structurally bounded (per-worker channels, `BATCH_FLUSH=256`, 4096-event cap); principle kept: per-tunnel/per-worker allocations bounded, speed-test shortlist small |
| R15 | Per-OS-native CI split for GUI/Android; `SHA256SUMS.txt` as `.dgst` replacement (§07 rows 2/10 alts) | Out of scope (no GUI/mobile); different jobs — dist `.sha256` attests *our* artifacts, `.dgst` verifies the *upstream xray zip*; keep both |

## 4. Fog graduated here (was "Not yet specified" on the map)

- **IPv6 parity:** new WARP paths (P0-5 junk, P1-4 gate, P0-7 pre-flight) are
  IPv4-pool-only, inheriting the existing opt-in v6 posture; bundle exports
  keep skip-with-warning / hard-error-when-only-v6 (`src/export.rs:283-312`);
  v6 MASQUE pools stay out with R2. No new v6 scope is created by this spec.
- **Speedtest policy:** no serial-vs-sample change. Opt-in `--speed-test`
  stays a capped shortlist sample (8 MiB/30 s, `src/engine/speed.rs:17-24`);
  torn rows (P0-6) never enter the shortlist; P1-5 only converts
  stall-errors into lower-bound records behind the same flag.
- **MASQUE crate: CLOSED as reject-this-cycle** (R2) — no quinn/h3 evaluation
  needed for execution.
- **Wizard text:** exact strings locked in P0-7(c) (from §06, reframed by §03
  blocked-vs-slow).
- **`find-fragment` shape:** locked as `tune fragment --config <uri> [--need 3]`
  inside P1-1 (subcommand, not scan flag, per §03 Resolution Q2).

## 5. Named follow-ups (genuinely open, out of this spec)

1. `self-update` platform matrix + npm-wrapper interplay (design ticket first;
   sketch input P1-7). 2. Peak-RSS measurement on a max-concurrency WARP scan
   (boringtun batch-buffer check; §07 row 7 optional). 3. `worers.dev`
   warn-only suggest on the phase-2 skip path (`src/engine/phase2.rs:330-333`;
   §04 row 8c candidate). 4. `tune` candidate-list defaults (`--candidates 50`,
   `--need-pct 30`, fragment `--need 3`) — confirm against live measurements
   at implementation time.

## 6. Execution rules (every implementation ticket inherits these)

Opt-in-only defaults (except P0-2, outcomes-identical); contract-first:
`ScanConfig` root stays non-strict (forward-compat `--retry-last` root) with
plain `#[serde(default)]` on new fields, nested `Phase2Config`/`WarpConfig`
keep `deny_unknown_fields` + `#[serde(default)]` (`src/api/types.rs:62,123,
131-132,176-177,198-204`); per-worker bounded channels + backpressured
`send().await`; `select!` + `ProbeContext::cancelled()` races in every new
probe loop; plain-push store + lazy `sort_if_dirty` (never read raw store
expecting order); 4096-event broadcast cap; per-controller `SocketCache`,
never hold its lock across `.await`; server pubkey resolved once per scan;
all fetches via `ranges::HTTP_CLIENT` with per-hop guard + call-site
`.timeout(...)`; secrets never reach logs; `.dgst` verify + 64 MiB caps on
xray downloads; stdout=machine/stderr=human with a contract test per new
output; tasks S/M (≤5 files); `cargo test` + `clippy --all-targets -- -D
warnings` + `fmt --check` before commit; versions/tags/publishing USER-GATED.
