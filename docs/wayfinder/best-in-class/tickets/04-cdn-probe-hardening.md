# 04: CDN probe hardening (SenPai ladder, SNI, WS, socks5h, burst fallback)

**Type:** research (AFK)

**Blocked by:** none

**Status:** resolved

## Question

Which SenPaiScanner probe-hardening tricks port to our CDN phase-1/phase-2,
exactly where: budget-split timeouts (`prober.go:269-275`), 5-host SNI
rotation (`prober.go:20-26,182-205`), WS-upgrade survival gate
(`probeWebSocket`), idle-hold veto (already have `--idle-hold-ms` — extend?),
`socks5h` + `ServerName` repair for IP dials (`runner.go:157-159,775-802`),
phase-2 fallback ladder (domain → tunnel-path → IP+SNI → public trace →
data-path, `runner.go:344-406`), parallel-burst throughput fallback
(8×16 KB, `727-766`), share-URL hardening set (`parser.go:417-537:
missing-?` recovery, `&`-in-path, `worers.dev` typo, truncated-JWT sanity)?

## Context

- Map each trick to `src/probe.rs`, `src/verify.rs`,
  `src/inline_verify.rs`, `src/xray.rs`, `src/socks.rs`,
  `src/configs.rs` with keep/drop + insertion point.
- Note what we already shipped in competitive-catchup (idle-hold, http
  probe, grpc/xhttp) to avoid double-counting.
- Deliverable: keep/drop table with file:line on both sides. Feeds 08.

## Answer

Research only — no code landed, no defaults changed. SenPai side refs are
`MatinSenPai/SenPaiScanner` paths from the ticket (no SenPai checkout in
this repo; semantics cross-checked against
`docs/research/competitor-cf-scanners-2026-09-03.md:19-72`). Our side lines
are current `src/` locations. `rust-engineering` skill is absent in this
session (load failed); mapping rests on direct reads of the files below.
Ticket 03 already decided budget-split (`03-auto-tune-adaptive.md:72-81`);
this ticket defers to it rather than re-deciding.

Already shipped (competitive-catchup — do NOT double-count): idle-hold
(`08-idle-hold.md`; `src/probe.rs:135-147,173-186,283-295`,
`src/api/types.rs:224`), HTTP/trace probe (`05-http-probe.md`;
`src/probe.rs:196-318`), grpc/xhttp parse+verify (`09-grpc-xhttp.md`;
`src/configs/uri.rs:289-311`, `src/xray.rs:79-95`,
`src/verify.rs:499-504`).

Global constraints for anything 08 adopts: defaults unchanged; new
`ScanConfig` root field = plain `#[serde(default)]` (root stays non-strict,
`src/api/types.rs:198-202`); new `Phase2Config`/`WarpConfig`/`CustomFragment`
field = `deny_unknown_fields` + `#[serde(default)]`
(`src/api/types.rs:131,176`); every new await sits inside the bounded-worker
+ `select!`/cancel race (`src/engine/phase2.rs:82-138`,
`src/engine/speed.rs:179-221,251-262`); secrets never reach logs
(`src/configs/mod.rs:59-74`, `src/engine/phase2.rs:375-407`,
`src/xray.rs:290-342`).

| # | SenPai trick (SenPai side) | Verdict | Our insertion point (our side) + notes |
|---|---|---|---|
| 1 | Budget-split timeouts (`prober.go:269-275`: TCP≤¼, TLS≤½ of budget) | KEEP (extend; 03 owns decision) | `src/probe.rs:110-155` (`TlsTransport::probe`, single outer `timeout` at `:133`) + `src/probe.rs:159-194` (`TcpTransport::probe`, single `timeout` at `:171`): wrap connect/handshake in per-step budgets reusing `step_budgets` (`src/probe.rs:218-223`, today HTTP-only at `:231-277`). Outer `timeout_ms` stays the ceiling; `reason()` strings (`:31-40`) unchanged. Always-on, no flag, per 03. |
| 2 | 5-host SNI rotation (`prober.go:20-26,182-205`) | KEEP opt-in rotation; DROP retry-all-5-per-IP | Phase-1 has one SNI only: `PROBE_SNI` (`src/probe.rs:17`), baked once in `TlsTransport::new` (`:86-93`) / `HttpTransport::with_shared` (`:208-215`) via `transport_for` (`:68-78`). Insert: SNI list param on those constructors + new `ScanConfig` root field (`#[serde(default)]`, default = today's single SNI). Rotate per probe call (worker index), never 5× dials per IP (cost). Phase-2 SNI *variants* already exist (`src/api/types.rs:136`, `src/engine/phase2.rs:34-38`, `src/xray.rs:53-59`) — not the same thing, no double-count. 08 picks rotation policy. |
| 3 | WS-upgrade survival gate (`probeWebSocket`) | DROP as phase-1 gate; phase-2 coverage already KEEP | Phase-1 has no WS check (`src/probe.rs` = tcp/tls/http only). WS is proven end-to-end in phase-2: non-inline transports route to xray (`src/verify.rs:499-504`), `wsSettings` emitted (`src/xray.rs:68-78`). A per-candidate phase-1 WS handshake is origin-dependent cost for no new signal. If 08 wants a cheap signal: opt-in post-phase-1 WS check reusing `XrayTunnelProbe` inside `verify_phase` (`src/engine/phase2.rs:21`), never in `probe.rs`. |
| 4 | Idle-hold veto (have `--idle-hold-ms` — extend?) | SHIPPED, keep as-is; DROP phase-2 extension | Shipped: `src/probe.rs:135-147,173-186,283-295` (latency at handshake, RST→`Refused("idle-hold RST")`), `src/api/types.rs:224,473-475`, `FakeTransport` (`:534-540`). Phase-2 already holds the tunnel across URLs (keep-alive reuse `src/inline_verify.rs:118-169`; one socks session per combo `src/verify.rs:253-271`) — a mid-verify RST already fails the candidate, so a separate idle sleep buys latency, not signal. WARP transports intentionally ignore idle-hold (known audit note) — out of scope. |
| 5 | `socks5h` + `ServerName` repair for IP dials (`runner.go:157-159,775-802`; cf. `verifyPeerCertByName` in research `:55-57`) | KEEP repair only; `socks5h` half already shipped | `socks5_connect` (`src/socks.rs:412-460`) already sends ATYP-domain (`:431-438`) = remote-resolve (`socks5h` equivalent) — no change. Repair point: `ServerName::try_from(host)` in `get_via_socks_inner` (`src/socks.rs:389-390`) + `timed_download_via_socks_inner` (`:298-299`) + inner handshake (`src/inline_verify.rs:229-237` via `tls_connector` `:228-239`, webpki roots). Insert one shared host→`ServerName` helper in `src/socks.rs` (explicit `IpAddr` parse fallback + bracket strip, mirroring `src/configs/mod.rs:293-299` / `src/configs/uri.rs:265-266`); outer-to-candidate already falls back to `IpAddress` (`src/inline_verify.rs:267-275`) and phase-1/inline-outer skips verification (`src/probe.rs:95-102`). No contract/default change. |
| 6 | Phase-2 fallback ladder, domain→tunnel-path→IP+SNI→public trace→data-path (`runner.go:344-406`) | KEEP as engine-level tier fallback; DROP in-probe ladder + DROP distinct "tunnel-path" step | Today: one tier only — `effective_probe_urls` (`src/api/types.rs:150-159`), ALL URLs must 200 over ONE tunnel (`src/verify.rs:253-271` `all_ok`; `src/inline_verify.rs:96-176`). Insert ladder in `verify_phase` (`src/engine/phase2.rs:21-62`): tier list `[user probe_urls] → [public trace + data-path]`; advance a tier only when the previous yields zero passes; stop at first tier with ≥1 pass. `TunnelProbe` trait (`src/verify.rs:37-48`) stays single-shot (injectable/offline tests). "Tunnel-path" collapses into probe-URL tiers (our tunnel IS the transport). Bound cost via existing `cap`/`stop_found`/`passed`-dedup (`:73-74,106-126`) + `select!` cancel (`:127-138`). New tier knobs (if any) need `#[serde(default)]` under `deny_unknown_fields`. 08 orders the tiers. |
| 7 | Parallel-burst throughput fallback, 8×16 KB (`runner.go:727-766`; cf. 128 KiB min-sample `cmds.go:716` in research `:41-42`) | KEEP as speed-test fallback only; DROP as verify gate | Shipped opt-in shortlist test: `SPEED_TEST_BYTES/TIMEOUT/CONCURRENCY/URL` (`src/engine/speed.rs:17-24`), `timed_download_via_socks` (`src/socks.rs:255-311`), `measure_endpoint` (`src/engine/speed.rs:140-145`), cancel-inside-cleanup (`:230-263`). Insert: on full-download stall/timeout, fall back to N parallel small burst fetches (8×16 KB analogue) and record a lower-bound MB/s instead of erroring. Keep behind `speed_test`, keep 8 MiB/30 s defaults, reuse `SPEED_TEST_CONCURRENCY` bound + `SpeedTester`/`TunnelOpener` seams (tests stay offline). DROP the 128 KiB-minimum-sample-before-verdict for phase-2 (slows every candidate; short-connection DPI kills are idle-hold's job, row 4). |
| 8a | Share-URL: missing-`?` recovery (`parser.go:417-537`) | KEEP (bounded pre-normalize) | `parse_uri` (`src/configs/uri.rs:18-33`) → `parse_sip002` (`:255-329`) uses `Url::parse` (`:256`); params without `?` silently vanish into defaults. Insert at `parse_sip002` head: single-pass reattach of trailing `&`/`=` segments as query when no `?` present. Errors still surface via subscription `ignored+errors` (`src/configs/subscription.rs:57-64`) / phase-2 skip warn (`src/engine/phase2.rs:330-333`). |
| 8b | Share-URL: `&`-in-path | DROP auto-join; encoder guarantee already KEEP | `query_pairs` split on raw `&` is correct; well-formed links encode it (`QUERY_VALUE_ENCODE_SET` includes `&`, `src/configs/uri.rs:42-57`; render path `:61-66`). Auto-joining is ambiguous (param vs path). Insert nothing; optionally document at `parse_sip002` type-dispatch (`:289-311`). |
| 8c | Share-URL: `worers.dev` typo | DROP auto-correct; KEEP warn-only candidate | Silent hostname rewrite = target mutation outside official lists/explicit input (AGENTS.md Never). Insert (if 08 wants it): suggestive `tracing::warn` ("did you mean `workers.dev`?") on the phase-2 skip path (`src/engine/phase2.rs:330-333`), never rewrite. |
| 8d | Share-URL: truncated-JWT sanity | KEEP early shape check; DROP strict JWT validation | `base64_any` already tries 4 variants (`src/configs/mod.rs:283-291`); oversize/empty rejected (`finish_spec` `:200-262`; tests `:664-680,798-826`). Truncated worker/JWT credentials currently die downstream (spawn/inline-UUID). Insert shape-only check in `parse_uri`/`finish_spec` (`src/configs/uri.rs:18-33`, `src/configs/mod.rs:200`): segment-count/base64url-decodability → actionable error pre-spawn. No signature checks, no new dependency. |
