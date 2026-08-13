# CF-Scanner

A single cross-platform Rust binary that finds working Cloudflare
IPs/endpoints on ISP-restricted networks.

- **CDN/proxy mode** — phase 1: TCP+TLS handshake scan of official Cloudflare
  IPv4 ranges; phase 2 (optional): verify candidates against a real proxy
  config (VLESS/Trojan/VMess/SS via an embedded Xray subprocess with
  DPI-bypass fragmentation + SNI variants).
- **WARP mode** — UDP endpoint discovery over Cloudflare WARP pools using a
  real WireGuard handshake probe (boringtun); optional verification with your
  own WireGuard/AmneziaWG config; opt-in config registration via Cloudflare's
  client API.

CLI, an interactive wizard, and a localhost browser UI all drive the same
in-process engine. Results are **last-scan-only, in memory**: no history, no
telemetry, nothing leaves your machine.

## Quick Start

```
cargo build --release
cargo run -- serve            # API + UI on http://127.0.0.1:8765
```

## Commands

| Command | Description |
|---------|-------------|
| `cargo run -- serve` | Start API + embedded UI on 127.0.0.1:8765 |
| `cargo run -- scan --mode cdn --preset quick --target 20` | One-shot CDN scan (JSON lines on stdout) |
| `cargo run -- scan --mode warp --ports 2408,500` | One-shot WARP scan |
| `cargo run -- ranges refresh` | Refresh bundled Cloudflare ranges (verified HTTPS fetch) |
| `cargo test` | Unit + integration tests |
| `cargo clippy --all-targets -- -D warnings` | Lint |
| `cargo fmt --check` | Format check |
| `dist plan` | Release dry-run (cargo-dist 0.32) |
| `dist build --artifacts=all --tag=v0.1.0` | Build release artifacts (normally via CI) |

## Architecture

- **One engine, one contract.** `ScanController` in `src/engine.rs` owns all
  scanning state; the API contract lives once in `src/api/types.rs`
  (`ScanConfig`, `Verdict`, `StopCondition`, events). CLI, wizard, HTTP server,
  and frontend are thin clients. The server maps engine types → API types;
  engine types are never serialized directly.
- **Phase 2 = Xray subprocess.** `xray run -c config.json` with a local socks
  inbound; fragment (DPI bypass) via a Freedom outbound + `sockopt.dialerProxy`
  chaining. The xray binary ships inside release archives (build-time
  download + `.dgst` SHA2-256 verification, feature `dist-bundle-xray`); dev
  builds fall back to a cached download in the data dir.
- **WARP probes.** boringtun builds a valid Init (MAC1 required, MAC2 zeros);
  a Response (92 B) or Cookie (64 B) of exact shape = open.
- **GeoIP.** db-ip.com Lite country MMDB embedded at build time
  (`include_bytes!` + maxminddb). Country is resolved offline per verdict.
  Data is CC BY 4.0 — attribution link in the UI footer.
- **Frontend.** One embedded HTML file (htmx + SSE, zero build step), served
  by the same binary.

Design rationale lives in [docs/decisions/](docs/decisions/).

## Platform Caveats

- **Windows SmartScreen.** Release binaries are unsigned, so SmartScreen
  shows a warning. Accepted trade-off for a free tool; see
  [ADR-001](docs/decisions/ADR-001-xray-subprocess-and-bundling.md) for the
  equivalent trade-off on the bundled xray.
- **Termux (Android).** Termux builds static musl, but the xray
  linux-arm64 release is glibc — install Termux's glibc package or use the
  runtime fallback download instead of the bundled binary.
- **Offline builds.** If the GeoIP download fails at build time, the binary
  still builds with an empty embedded database (countries show "unknown").
  The xray bundle is only attempted for release builds, never dev builds.

## Security

- Binds to 127.0.0.1 only, unless an explicit bind flag is given.
- Imported configs and keys are never logged or transmitted.
- Downloaded binaries are checksum-verified against pinned versions
  (`data/xray-version.txt`, `data/geoip-version.txt`).
- No history, no telemetry: results live in memory only; `reset` clears them.

## Documentation

- `docs/intent/cf-scanner.md` — confirmed user intent + verified research
- `docs/spec.md` — the approved spec
- `docs/development.md` — local build + test flow
- `docs/release-process.md` — versioning control + publishing pipeline
- `docs/decisions/` — architecture decision records
- `tasks/plan.md`, `tasks/todo.md` — implementation plan and task list
