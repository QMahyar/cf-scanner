# Competitor research: Cloudflare IP scanner projects (2026-09-03)

Repos cloned to `C:\Users\qmahyar\.cache\opencode\repos\` for inspection.
All claims read from source at each repo's default branch.

| Project | Stars | Language | Updated |
|---|---|---|---|
| [MatinSenPai/SenPaiScanner](https://github.com/MatinSenPai/SenPaiScanner) | 2364 | Go | 2026-08-03 (v1.0.0) |
| [MortezaBashsiz/CFScanner](https://github.com/MortezaBashsiz/CFScanner) | 1827 | Bash/Docker/Win/Py/Go/Android | multi-impl |
| [vfarid/cf-ip-scanner](https://github.com/vfarid/cf-ip-scanner) | 508 | JS (browser) | single-page app |
| [amir0zx/CrimsonCF](https://github.com/amir0zx/CrimsonCF) | 80 | TS web + Docker | web app |
| [amirrezas/WaldonCFscanner](https://github.com/amirrezas/WaldonCFscanner) | 12 | Python (TUI) + APK | 4-stage pipeline |

Also surveyed (not cloned): ircfspace/scanner (164), radioactiveAHM/cf-scanner
(154), DevoTalk/fast-cf-ip-scanner (29), m-rambod/CFScanner (10),
F4RAN/web-cf-scanner (9), unknowingpro/sinadalvand CFScanner (Android forks of
Morteza's), gh-tt/cloudflare-scanner (110), proarash/go-cf-scanner (2).

## SenPaiScanner (MatinSenPai) — closest architectural cousin

One Go engine, three frontends: Wails desktop GUI ("Signal Desk"), native
Kotlin/Compose Android app, Bubble Tea TUI. MIT. v1.0.0 (2026-08-03).

### Interfaces & workflow
- TUI pages: Home, Quick Scan (count/workers/timeout presets), Scan Config,
  Live Scan, Results, Colos, Live Colos, About, Scan-with-Config (Phase 1 →
  Phase 2). Remembers last scan config in `%AppConfigDir%/senpaiscanner/config.json`
  → "Retry Last Scan".
- Desktop/Android: Scan / Results / Export workspaces; live copy of green
  results or top-20 mid-scan; cancellation preserves discovered results.
- CLI entry `cmd/senpaiscanner/main.go` is TUI-first (`--version` flag);
  file mode = `ips.txt` next to binary/cwd (plain IP, CSV first field, CIDR;
  `#` comments; shuffled).

### Discovery (phase 1)
- Embedded CF v4+v6 ranges, weighted random sampling by subnet size; optional
  extra CIDRs (exact scope when builtin off); "MahsaNG V4 stream" variant.
- Probe modes: tcp | tls | http (HTTPS GET `/cdn-cgi/trace`). Multi-port,
  configurable workers (default 50)/timeout (5s)/tries (4)/count (500).
- SNI rotation over 5 well-known CF hostnames (DPI evasion); optional fixed SNI.
- HTTP health adds: 128 KiB download sample (deliberate — DPI kills short
  connections before verdict, comment in `internal/ui/cmds.go:716`), optional
  WebSocket-upgrade requirement, and a post-200 **idle-hold stability probe**
  (DPI allows first GET then RSTs; comment `prober.go:140`).
- Optional **neighbor scanning** (off by default): on each healthy hit, queue
  N neighbor IPs of the same /24 (radius/per-hit/max-total capped).
- **Colo discovery mode**: dedicated 300-IP scan that lists accessible PoPs;
  **colo filter** (`colo` param) to accept only specific PoPs.
- Live stats: tested/healthy/failed/in-flight; per-result latency, loss, TLS ok,
  HTTP status, colo, throughput, WS ok.
- ISP/ASN metadata: `speed.cloudflare.com/meta` + IPWhois + IPinfo merge with
  Team Cymru DNS fallback (`internal/ui/ir_isps.go`).

### Phase 2 (validation & speed)
- Parses `vless://`, `trojan://`, `vmess://` share links; transport-aware
  (tcp/ws/grpc/xhttp-splithttp), TLS fingerprint/ALPN, `verifyPeerCertByName`
  for literal IPs (allowInsecure removed from xray-core 2026-06-01 — they
  track xray HEAD).
- Embedded/official xray binary, SOCKS inbound, connectivity check → TTFB →
  download throughput → optional upload test; min-speed gate; top-N candidates
  promoted to Phase 2 (10 workers).
- Post-stop **speed test on the green shortlist** (separate action).

### Export
- Rewritten share URLs per endpoint (template URL with IP:port swapped),
  base64 subscription, sing-box JSON, Clash YAML, raw endpoint list, clipboard.

### Not in SenPaiScanner
- No WARP/UDP mode, no DPI fragmentation (no xray `fragment` block anywhere in
  repo), no GeoIP/country lookup (colo only), no headless/agent JSON output
  (TUI is the only CLI surface), no xray binary download/verify machinery
  (expects binary present), no presets beyond the three quick-pick rows.

## CFScanner (MortezaBashsiz)

Six implementations of one idea (bash, docker, windows, python, go, android).
Go impl: cobra CLI — `--threads --config --vpn --loglevel --subnets --shuffle
--upload --fronting --tries --download-speed --upload-speed --download-time
--upload-time --fronting-timeout --download-latency --upload-latency --writer
csv|json`. Requires a config.real (UUID/host/port/path/SNI for a vmess+ws+tls
backed domain). If `--vpn`, spawns xray-core per candidate IP and speed-tests
through the real tunnel (download + optional upload + fronting test); interim
CSV/JSON results. No IP-source discovery beyond given subnet file (ships a
default), no TUI/wizard, no WARP, no fragmentation, no export formats beyond
CSV/JSON of results.

## vfarid/cf-ip-scanner

Browser-only single HTML page + JS. Random IP sampling from CF ranges
(30 IPs per /24), HTTP(S) latency probes with max-latency threshold, spinner-
style progress animation, sorted table, per-IP and copy-all. No TLS details,
no config validation, no export files, no CLI. Runs from any static host (or
GitHub Pages); zero install is its whole value proposition.

## CrimsonCF (amir0zx)

Dockerized web app (Vite/TS + probe server). L4 TCP-handshake-only probing
(deliberately not HTTPS — README argues SNI/cert issues make HTTPS probing
unreliable), concurrency control, IP range groups (CDN / Tunnel / WARP /
Custom / All) with paging, sources fetched from URLs/APIs + official CF
presets, capability tags (CDN/Tunnel/WARP/BPB heuristics), history, exports
TXT/JSON/XLSX + Xray/sing-box/Clash configs, and a **Cloudflare DNS tab** that
pushes fastest IPs into A records (replace mode). No real-config verification
(they consider HTTPS unreliable), no WARP UDP probing (only range grouping).

## WaldonCFscanner (amirrezas)

Python Textual TUI (+ packaged Windows exe and Android APK). 4-stage pipeline:
TCP probe → TLS+SNI handshake → pure-Python 1 MB `speed.cloudflare.com/__down`
throughput gate → headless xray-core VLESS/WS verification with TTFB.
Auto-downloads/ensures xray; embedded ipv4/ipv6/domain lists (overridable by
placing files next to exe); "hot-subnet" feedback loop (TLS-successful /24s get
focused resources); stratified first-octet randomization; hardware-aware
concurrency caps (epoll on Linux, 1000-socket cap on Windows); bounded queues
with backpressure; bi-directional vless-URL ⇄ xray-JSON parser; clipboard URI
paste; CSV/log outputs. No WARP, no fragmentation, no GeoIP, no agent output.

## Feature comparison vs CF-Scanner (this repo)

| Feature | CF-Scanner | SenPai | Morteza | vfarid | CrimsonCF | Waldon |
|---|---|---|---|---|---|---|
| Language | Rust | Go | Go/bash/py | JS | TS | Python |
| CLI headless/agent JSON (stdout NDJSON, `--json-errors`) | ✅ | ❌ (TUI only) | ❌ | ❌ | ❌ (web) | ❌ |
| Interactive wizard/TUI | ✅ | ✅ (Bubble Tea) | ❌ | ❌ | web UI | ✅ (Textual) |
| TCP phase 1 | ✅ | ✅ | ❌ (tls/vpn only) | HTTP | ✅ | ✅ |
| TLS phase 1 | ✅ | ✅ | ✅ | ✅ (https opt) | ❌ | ✅ |
| HTTP/trace probe (`/cdn-cgi/trace`) | phase 2 colo | ✅ | ✅ | ✅ | ❌ | ✅ |
| WebSocket-requirement check | ✅ (phase 2 ws) | ✅ opt | ✅ (ws always) | ❌ | ❌ | ✅ |
| SNI rotation / SNI variants | ✅ (variants) | ✅ (rotate 5) | ❌ | ❌ | ❌ | ✅ (clean SNI) |
| Embedded CF ranges + refresh | ✅ (refreshed-ranges.json) | ✅ (embed only) | ✅ (file) | ✅ (embed) | ✅ (URL sources) | ✅ (embed) |
| CIDR/custom input | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| IPv6 | ✅ (v6 supported in src) | ✅ (opt-in) | ❌ (v4 only) | ❌ | ✅ (groups) | ✅ (list) |
| Multi-port scan | ✅ | ✅ | single | single | ✅ | single (443) |
| Presets (target/cap/fragment) | ✅ | partial (3 quick rows) | ❌ | ❌ | ❌ | ❌ |
| Phase 2 real-config verify (xray subprocess) | ✅ | ✅ | ✅ | ❌ | ❌ | ✅ |
| Protocols verified | vless/trojan (+ws, tls) | vless/trojan/vmess | vmess+ws+tls | — | — | vless/trojan |
| Transports parsed | ws (+grpc xhttp per xray) | tcp/ws/grpc/xhttp | ws | — | — | ws/grpc/tcp |
| **DPI fragmentation presets** (xray fragment + dialerProxy) | ✅ light/med/heavy | ❌ | ❌ | ❌ | ❌ | ❌ |
| GeoIP country (offline mmdb) | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Colo (PoP) per result | ✅ (phase 2 trace) | ✅ (phase 1 trace) | ❌ | ❌ | ❌ | ❌ |
| Colo filter / colo discovery | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ |
| **WARP UDP mode (WG handshake probes, boringtun)** | ✅ | ❌ | ❌ | ❌ | ❌ (groups only) | ❌ |
| WARP config gen/export/registration | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Throughput/speed measurement | phase 2 verify only | ✅ (+upload) | ✅ (+upload) | ❌ | ❌ | ✅ |
| Min-speed / max-latency gates | partial (verdict) | ✅ (min speed) | ✅ (many knobs) | ✅ (latency) | filters | ✅ |
| Post-stop shortlist speed test | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ |
| Idle-hold stability probe | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ |
| Neighbor / hot-subnet feedback | ❌ | ✅ (opt-in) | ❌ | ❌ | ❌ | ✅ |
| Live results mid-scan | ✅ (events) | ✅ | ✅ | ✅ | ✅ | ✅ |
| Cancellation preserves results | ✅ | ✅ | ❌ | ❌ | ✅ | ✅ |
| Export: raw/csv/json | ✅ | partial | csv/json | txt | ✅+xlsx | csv |
| Export: base64 subscription | ✅ | ✅ | ❌ | ❌ | ❌ | ✅ |
| Export: sing-box | ✅ | ✅ | ❌ | ❌ | ✅ | ✅ |
| Export: clash | ✅ | ✅ | ❌ | ❌ | ✅ | ✅ |
| Share-URL rewrite per endpoint | ✅ (export-config) | ✅ | ❌ | ❌ | ✅ | ✅ |
| xray download/verify (.dgst, pinned) | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ (auto-download) |
| GUI (desktop/Android) | ❌ (pure CLI by design) | ✅✅ | android only | web | web | apk |
| Secrets hygiene (no config/key logging) | ✅ (enforced) | ✅ (README) | ⚠️ | n/a | n/a | ⚠️ |
| Injected transports / offline tests | ✅ | partial | ❌ | ❌ | ❌ | ❌ |

## Takeaways

1. **Our unique features**: WARP UDP discovery with real WireGuard handshake
   probes (nobody else does L4-UDP WARP probing; CrimsonCF merely has a WARP
   range group), DPI fragmentation presets for phase 2 verification (unique
   among all six), offline GeoIP country, agent-grade JSON contract, and
   verify-checksummed pinned xray delivery.
2. **SenPaiScanner is the feature leader on CDN mode** and the closest rival:
   its phase-1 hardening ideas are worth studying — idle-hold stability probe
   (DPI RST-after-200 detection), 128 KiB minimum download sample to defeat
   "DPI kills short connections" false positives, SNI rotation list, colo
   filter/discovery, post-stop shortlist speed test, and neighbor scanning
   (opt-in). Its persistence of last-scan config ("Retry Last Scan") is also a
   nice UX we lack (we keep last-scan results only, no config memory).
3. **Morteza CFScanner** has the richest verification knob set (download/
   upload speed+latency+time limits, fronting test, tries, shuffle) but is
   vmess+ws+tls-only and requires an external config file; no discovery
   intelligence.
4. **Waldon** validates the same two-phase architecture we chose (TCP → TLS →
   speed → xray) and adds hot-subnet mining + hardware-aware concurrency caps
   + bounded-queue backpressure (we already have bounded per-worker channels).
5. **CrimsonCF**'s differentiators are operational: scan history, DNS-record
   auto-update, XLSX export, URL-based range sources. Web-only delivery.
6. Nobody else ships an agent/JSON contract or checksum-verified xray
   provisioning; almost nobody else tests with injected transports.
