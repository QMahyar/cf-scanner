# Competitor scan: popular Cloudflare IP scanner projects

- Date: 2026-09-03
- Question: what features do popular CF scanner projects have that CF-Scanner lacks?
- Method: GitHub repo search API (`q=cloudflare+scanner`, sorted by stars) + raw READMEs of each project; feature list grounded against `docs/spec.md`, `docs/intent/cf-scanner.md`, and the current `src/api/types.rs` `Verdict`/`Phase2Verdict` fields and `src/export.rs` formats.

## Projects examined

| Project | Stars | Language | Status | Relevance |
|---|---|---|---|---|
| [XIU2/CloudflareSpeedTest](https://github.com/XIU2/CloudflareSpeedTest) | 28,861 | Go | active (pushed 2026-08-23) | The benchmark for latency/speed testing + region filtering |
| [ip-scanner/cloudflare](https://github.com/ip-scanner/cloudflare) | 3,741 | n/a | active | Not a scanner: curated CF IP-list repo for a Telegram channel (t.me/ipscan_channel); README is empty |
| [m0rtem/CloudFail](https://github.com/m0rtem/CloudFail) | 2,682 | Python | stale (pushed 2024-03) | Different category: DNS-misconfig recon to de-anonymize CF-protected sites; not endpoint scanning |
| [MatinSenPai/SenPaiScanner](https://github.com/MatinSenPai/SenPaiScanner) | 2,364 | Go | active | **Closest competitor**: two-phase scan + embedded Xray validation + client exports, CLI/TUI + GUI + Android |
| [MortezaBashsiz/CFScanner](https://github.com/MortezaBashsiz/CFScanner) | 1,827 | Kotlin/bash/python/golang/docker | active | Multi-implementation scanner with download/upload tests against a real vmess+ws+tls config |
| [barry-far/V2ray-Configs](https://github.com/barry-far/V2ray-Configs) | — | — | **disabled by GitHub Staff (ToS violation)** | Was a config aggregation/subscription repo (vmess/vless/trojan/ss lists); no live code to audit |
| [v2fly/v2ray-core](https://github.com/v2fly/v2ray-core) | — | Go | active | Reference only: protocol/transport surface our xray-backed verification could cover |

Note: our own `docs/research/2026-08-23-ui-v2-research.md` already mined XIU2 and `peanut996/CloudflareWarpSpeedTest` (WG handshake probes) for WARP-mode precedents; this doc covers the CDN-scanner side.

## Per-project notes

### XIU2/CloudflareSpeedTest (cfst)

Pure CDN speed tester (no proxy validation, no WARP; explicitly declined WARP support in discussion #392).

- Two latency modes: TCPing (default, 1s timeout) and HTTPing (2s timeout, headers-only).
- HTTPing filters by HTTP status code (`-httping-code`, default accepts 200/301/302).
- Download throughput test against a user-supplied URL (`-url`), timed per IP (`-dt`, default 10s).
- **Region (colo) filtering during phase 1** (`-cfcolo HKG,NRT,...`): reads the colo code from HTTP response headers — works because HTTPing/download hit the edge directly. Supports multiple CDNs' header conventions (Cloudflare/Fastly/CloudFront use IATA codes, CDN77/Bunny 2-letter country codes, Gcore city codes).
- Result filters: avg-latency upper AND lower bounds (`-tl`, `-tll` — lower bound exists to dodge low-latency-but-throttled routes), packet-loss upper bound (`-tlr`), download-speed lower bound (`-sl`).
- Stop condition on quality: keep downloading until `-dn` IPs satisfy `-sl` (our stop conditions are count/cap/duration, never quality-gated on speed).
- Per-result metrics: sent/received probes, loss rate, avg latency, download MB/s, colo code.
- Sampling: one random IP per /24 by default; `-allip` scans everything (v4 only for -allip).
- IPv4+IPv6 mixed range files (curated `ipv6.txt` from bgp.he.net prefixes).
- CSV output (`result.csv`, note re Excel mojibake), top-N display (`-p`), `-debug` mode that prints the exact per-IP failure reason (reset / 403 / timeout / TLS mismatch / cert expired...) for download+HTTPing phases.
- Warning surfaced in README: CF ToS prohibits proxying via CF (discussions #382/#383).
- Ecosystem: Android app wrappers, hosts auto-update scripts (discussions #312/#71).

### MatinSenPai/SenPaiScanner (closest competitor)

Go; CLI/TUI (Termux-friendly), Wails desktop GUI, Android app. MIT. Workflow = discover → validate → speed-test shortlist → export.

- Two-stage pipeline like ours: fast edge probing, then **embedded-Xray end-to-end validation of the best candidates**.
- **Post-stop speed test**: stop discovery once enough green results, then throughput/TTFB-test exactly that shortlist (decouples the expensive step from discovery).
- **Neighbor scanning (opt-in, off by default)**: after a hit, probe nearby addresses of the same /24 neighborhood.
- **Proxy-aware probing from share links**: `vless://`, `trojan://`, `vmess://` — derives SNI, host, path, TLS, port, and transport for the probe itself.
- **Transport-aware config parsing: TCP, WebSocket, gRPC, XHTTP/SplitHTTP** (ours is ws-only per spec).
- Exports: raw `ip:port` list, **rewritten share URLs** (original link re-hosted onto each passing endpoint), Base64 subscription, Sing-box JSON, Clash YAML. We cover base64/raw/singbox/clash but not per-endpoint link rewriting.
- Metadata: **ISP/ASN detection merging Cloudflare, IPWhois, IPinfo with Team Cymru DNS fallback** (ours: offline mmdb country + phase-2 colo; no ASN/ISP).
- Live results UX: copy single / all-green / top-20 mid-scan; cancellation preserves results (our cancel does too).
- Weighted random sampling across embedded ranges; file input accepts plain IP, CSV-first-field, or CIDR lines, `#` comments.
- TUI persists last scan config ("Retry Last Scan").
- Live per-result fields: health, latency, **loss**, throughput, colo, port, status.

### MortezaBashsiz/CFScanner

Bash (canonical) + python/golang/kotlin/docker/windows ports. Tests IPs against your real vmess+ws+tls front (id/host/port/path/SNI in a JSON config).

- Download, upload, or both (`-t DOWN|UP|BOTH`) measured through the working proxy.
- Speed threshold filter in KB/s (`-s`) — keep only IPs above it.
- Parallel worker count (`-p`), retries per IP (`-n`).
- **Success-count thresholds**: with N tries, require ≥D successful downloads AND ≥U successful uploads (`-d`, `-u`, AND-combined) — retries-as-reliability rather than one-shot probes.
- Random sample of size R per subnet (`-r`) instead of full /24 sweep.
- Custom subnet file or custom IP list (`-f`), SUBNET vs IP mode (`-m`).
- Result file per run named `YYYYMMDD-HHMMSS-result.cf` in `result/` (we are last-scan-in-memory only).
- Packaging breadth: docker image, Android, one implementation per ecosystem.

### barry-far/V2ray-Configs

Repository **disabled by GitHub Staff for ToS violation** (verified 2026-09-03). Historically: aggregated/normalized subscription files by protocol and country, refreshed hourly, used as raw subscription URLs. No CLI. Takeaway: public config aggregation is a ToS-risky category; nothing to adopt.

### ip-scanner/cloudflare

3.7k stars but no code — README is effectively empty; it distributes current CF IP lists via a Telegram channel. Takeaway: users want pre-filtered IP lists; our `ranges refresh` already covers the source-of-truth part.

### v2fly/v2ray-core (reference)

Confirms the transport/protocol surface worth supporting in phase-2 verification configs: vmess/vless/trojan/ss + ws, gRPC, QUIC, HTTP/2, SplitHTTP/XHTTP. Our phase 2 verifies ws transports only (spec: "ws transports"); grpc/xhttp verification is a real coverage gap for users whose fronts ride other transports.

## Feature gaps vs CF-Scanner (consolidated)

Legend: ⛔ = conflicts with a documented decision in `docs/intent/cf-scanner.md`; ✅ = actionable; ☁️ = ecosystem/packaging idea.

**Measurement & filtering**
1. ✅ **Packet-loss rate** per IP (sent/received over N probes) — we store a single `latency_ms` (`src/api/types.rs:212`); every competitor ranks on loss too.
2. ✅ **Latency lower bound** (`-tll`-style) — cheap filter for "low latency but throttled" routes; XIU2 documents the use case.
3. ✅ **Region/colo filter at scan time** (`--colo HKG,NRT`) — we record colo in phase 2 but cannot ask for "only these regions"; cfst does it in phase 1 via HTTP header.
4. ⛔ **Download/upload throughput testing** — explicit user decision ("NO download/speed tests: data- and time-hungry", intent line 68); SenPai's "post-stop speed test of the green shortlist" and CFScanner's `-t BOTH` are the patterns to revisit if that decision ever flips.
5. ✅ **Retry-with-thresholds probing** (N tries per IP, require ≥D successes) — reliability signal, cheap to add to phase 1; CFScanner's `-n/-d/-u`.
6. ✅ **HTTPing-style probe mode** (HTTP latency + status-code acceptance + header colo) — an alternative phase-1 classifier; cfst's default second mode.
7. ✅ **Debug mode printing per-IP failure reasons** for the failing phase — we already carry `Phase2Verdict.error`; a phase-1 equivalent (reset vs timeout vs TLS) is missing.

**Config & proxy handling**
8. ✅ **gRPC / XHTTP-SplitHTTP / HTTPUpgrade transport support** in parsed and verified configs — SenPai parses all four; we verify ws only (spec line 23). v2ray-core reference lists the full surface.
9. ✅ **Share-link rewriting export**: for each passing endpoint, re-emit the user's original `vless://`/`vmess://`/`trojan://` link with the winning `ip:port` (SenPai's marquee export; we only rewrite during `export-config --config vless://... --ip --port` for one endpoint at a time).
10. ✅ **Probe parameters derived from the share link** (SNI/host/path/TLS/port feed the phase-1 probe) — we verify end-to-end but phase 1 stays transport-agnostic.

**Ranges & sampling**
11. ☁️ **Opt-in neighbor scan** (SenPai): after a hit, widen within the same neighborhood — we deliberately skip dense /24s; this is the controlled way to offer depth.
12. ✅ **Curated IPv6 working-range file** shipped (cfst's `ipv6.txt` from bgp.he.net) — we support IPv6 opt-in since v0.2.0 but ship no working-v6 shortcut list.
13. ☁️ **Multi-CDN header parsing** (colo from CloudFront/Fastly/Gcore/CDN77/Bunny responses) — only relevant if CF-only scope ever widens.

**Output & UX**
14. ✅ **Richer CSV columns** (sent/received/loss) once #1 exists; cfst's CSV is the de-facto schema.
15. ☁️ **Dated result files** (`result/20230120-203358-result.cf`) — we are last-scan-only by decision; only revisit if history ban lifts.
16. ☁️ **Docker image**, Android app, GUI — ⛔ contradicts "pure CLI + wizard" (AGENTS.md 2026-09-02); listed for completeness.
17. ☁️ **Hosts-file integration / auto-update scripts** — out of product scope, common user follow-up (cfst discussions #312/#71).

## What we already have that they don't

For balance: xray-backed phase-2 verification with DPI-fragment presets (nobody in this set does fragmentation), WARP UDP mode with WireGuard handshake probes, `deny_unknown_fields` typed contract, agent-mode NDJSON output, embedded offline GeoIP, bounded-channel dispatch with cancellation racing in-flight probes.

## Sources

- https://raw.githubusercontent.com/XIU2/CloudflareSpeedTest/master/README.md (+ repo API for star count)
- https://raw.githubusercontent.com/MatinSenPai/SenPaiScanner/main/README.md
- https://raw.githubusercontent.com/MortezaBashsiz/CFScanner/main/bash/README.md
- https://github.com/barry-far/V2ray-Configs (disabled notice)
- https://api.github.com/repos/ip-scanner/cloudflare + empty README
- https://raw.githubusercontent.com/v2fly/v2ray-core/master/README.md
- GitHub search API: `q=cloudflare+scanner&sort=stars`
