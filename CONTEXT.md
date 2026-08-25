# CF-Scanner context map

Progressive context: start at Layer 1. Load a Layer 2 section only for the
module you touch. Follow pointers into Layer 3 deep docs when a decision
matters. The domain glossary lives at the bottom.

## Layer 1: Orientation

One cross-platform Rust binary (`cf-scanner`) finds working Cloudflare IPs
and endpoints on ISP-restricted networks. It scans in two modes. CDN/proxy
mode runs a TCP/TLS phase-1 scan plus an optional xray-backed phase 2 with
DPI fragmentation. WARP mode sends UDP WireGuard handshake probes, verifies
optionally with your wgconf, and can register a config if you opt in. One
in-process engine (`ScanController`) serves the CLI, the wizard, the axum
HTTP API on localhost, and the embedded Svelte 5 UI as thin clients.
Results are last-scan-only, with no history and no telemetry, bound to
127.0.0.1.

Read next (pick by task, not wholesale):
- Changing behavior or the API: `docs/spec.md`, plus ADR-011 before touching
  the contract
- Building or releasing: `docs/development.md`, `docs/release-process.md`
- Why something is the way it is: the ADRs in `docs/decisions/`
- What changed lately: `CHANGELOG.md`

## Layer 2: Module map

| Module | Files | Owns | Read next |
|---|---|---|---|
| API contract | `src/api/types.rs` | ScanConfig/Verdict/StopCondition/events, validation caps (`MAX_*`), `deny_unknown_fields` payloads | ADR-005, ADR-011 |
| Engine | `src/engine/{mod,cdn,warp,phase2,plan}.rs` | Orchestration, stop conditions, per-worker queues, cancellation (`select!` over probes), verdict store (push + lazy `sort_if_dirty`), SSE event broadcast (4096) | spec §6 tests |
| HTTP server | `src/server/{mod,state,error,guard,sse}.rs` | Routes, localhost-only middleware (Host/Origin/Sec-Fetch-Site), error envelopes with machine `code`, SSE `TerminalBounded` (survives Lagged), profiles/ranges persistence | ADR-010 |
| Probe (phase 1) | `src/probe.rs` | TLS handshake probe + latency; injectable `Transport`; `no_verify_client_config` (probe/tunnel use ONLY) | intent correction #3 |
| Phase-2 verify | `src/verify.rs`, `src/inline_verify.rs`, `src/xray.rs`, `src/socks.rs` | Inline VLESS/Trojan wire protocol vs xray subprocess paths; trial-dir hygiene; xray binary lifecycle (`.dgst` verify, zip caps, memo re-stat); fragment/SNI config builder | ADR-001, ADR-004 |
| WARP probe | `src/warp.rs` | Pools, boringtun Init probe, shape-only open classification, full-session wgconf verification, per-controller `SocketCache` | ADR-002 |
| WARP identity | `src/warpgen.rs`, `src/wgconf.rs` | v0a884 registration client (typed `WarpRegisterError`), identity persistence, WireGuard/AmneziaWG parse/render | intent WARP section |
| Ranges & fetch | `src/ranges.rs` | CF pools (bundled + refreshed), CIDR grammar/sampling, shared `HTTP_CLIENT` (per-hop SSRF guard, NO global timeout) | ADR-003 |
| GeoIP | `src/geo.rs` | Offline country via embedded mmdb; colo via /cdn-cgi/trace | ADR-003 |
| Config parsing | `src/configs.rs` | vless/trojan/vmess/ss URI, subscription, and xray JSON ingestion; secret sanitization | (none) |
| CLI surface | `src/main.rs`, `src/cli_wizard.rs` | clap subcommands (serve/scan/wizard/ranges/warp-config/export-config), NDJSON stdout, TTY-gated stderr ticker, wizard | spec §3 |
| UI | `ui/src` (Svelte 5 runes) → committed `ui/dist` (rust-embed) | Beginner/Pro modes, EN/FA RTL, validators mirroring server grammar, SSE client with reconnect re-hydrate | `docs/ui-research-report.md` (annotated) |
| Packaging | `build.rs`, `dist-workspace.toml`, `wix/`, `.github/workflows/`, `npm/cf-scanner/` | GeoIP/xray build-time bundling (checksummed), dist matrix (linux x86_64/aarch64 + windows), npm wrapper (sha256-verified installs), CI gates + version-parity job | ADR-007..010 |

## Layer 3: Invariants that span modules

(v0.8.0; the canonical list lives in `AGENTS.md` under "v0.8.0 invariants")

1. Everything serializes through `api::types`; engine types never reach the
   wire.
2. Every network call sets its own timeout; every loop checks stop/cancel.
3. Cancellation races probes (`select!` + `ProbeContext::cancelled()`).
4. Store order comes only from `results()` (lazy sort); dispatch is per-worker.
5. Fetches go through `ranges::HTTP_CLIENT` (redirect-guarded, per-call timeout).
6. Error envelopes always carry `code`; secrets never reach messages/logs.
7. Release bumps touch three files atomically (Cargo.toml, npm
   package.json, and install.js RELEASE_TAG) or the CI version-parity job
   fails. Every bump, tag, and publish is USER-GATED: agents propose the
   version and wait for an explicit yes before shipping anything.

## Glossary (domain model)

### Verdict

The classification of a scanned endpoint as working or not. The verdict is
binary and lives in the engine. The results row IS the verdict: a row
existing means the endpoint works, and a missing row means it doesn't.

### Working

An endpoint that satisfies its mode's verdict rule:

- **WARP**: every handshake probe responded (open AND zero probe loss). A
  single dropped probe excludes the endpoint. Lossy endpoints are not
  reported and never listed.
- **CDN phase 1**: the TCP/TLS probe connected.
- **Phase 2**: the config URI verified over the candidate.

### Probe loss

The share of handshake probes to one endpoint that got no response,
`failed / probes * 100`. For WARP rows it is always 0.0 because any loss
excludes the row. The probes-per-endpoint setting therefore controls how
strictly "working" is judged, not just measurement accuracy.

### Open endpoint

A WARP endpoint that answered at least one probe with a Response or Cookie
packet. Open is necessary but not sufficient for Working: the endpoint must
also have zero probe loss.
