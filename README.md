# CF-Scanner

A single cross-platform Rust binary that finds working Cloudflare
IPs/endpoints on ISP-restricted networks.

- **CDN/proxy mode** — phase 1: TCP+TLS handshake scan of official Cloudflare
  IPv4 ranges; phase 2 (optional): verify candidates against a real proxy
  config (VLESS/Trojan verified in-process, VMess/SS via an embedded Xray
  subprocess — with DPI-bypass fragmentation + SNI variants).
- **WARP mode** — UDP endpoint discovery over Cloudflare WARP pools using a
  real WireGuard handshake probe (boringtun); optional verification with your
  own WireGuard/AmneziaWG config; opt-in config registration via Cloudflare's
  client API.

CLI, an interactive wizard, and a localhost browser UI all drive the same
in-process engine. Results are **last-scan-only, in memory**: no history, no
telemetry, nothing leaves your machine.

## Quick Start

### Download

Get the latest release from
[GitHub Releases](https://github.com/QMahyar/cf-scanner/releases):

- **Windows** — the MSI installer (easiest; upgrades in place) or the
  portable zip
- **Linux (x86_64 / aarch64)** — one-line shell installer:

  ```sh
  curl -LsSf https://github.com/QMahyar/cf-scanner/releases/latest/download/cf-scanner-installer.sh | sh
  ```

- **Any platform** — the portable zip/tarball: extract anywhere and run
  `cf-scanner` directly (no install step)

### Run

```sh
cf-scanner serve     # API + UI on http://127.0.0.1:8765
```

Then open <http://127.0.0.1:8765> in your browser. Prefer a different port?
`cf-scanner serve --port 9000`.

On Windows, `cf-scanner serve --tray` keeps the app running from the system
tray instead of a terminal: the tray menu starts CDN/WARP scans, cancels
them, opens the UI, and exits `serve` gracefully. Adding `--autostart` (with
`--tray`) registers the app to start with Windows via a `CF-Scanner` entry
under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` (see
`docs/qa-runbook.md` §5 for the manual tray/autostart checks).

### Build from Source

```sh
cargo build --release
cargo run -- serve    # API + UI on http://127.0.0.1:8765
```

Rust 2024 toolchain required; see `docs/development.md` for the full local
flow. Building needs network for the one-time GeoIP download unless
`CFSCANNER_OFFLINE_BUILD=1` is set (see Platform Caveats → Offline builds).

## Commands

Installed binary: use `cf-scanner`. Running from source: replace `cf-scanner`
with `cargo run --`.

| Command | Description |
|---------|-------------|
| `cf-scanner serve` | Start API + embedded UI on 127.0.0.1:8765 |
| `cf-scanner scan --mode cdn --preset quick --target 20` | One-shot CDN scan (JSON lines on stdout) |
| `cf-scanner scan --mode warp --ports 2408,500` | One-shot WARP scan |
| `cf-scanner wizard` | Interactive wizard over the same engine |
| `cf-scanner warp-config generate` | Opt-in WARP registration (v0a884 API) + wgconf build |
| `cf-scanner warp-config export` | Export the registered WARP config as text/.conf |
| `cf-scanner ranges refresh` | Refresh bundled Cloudflare ranges (verified HTTPS fetch) |
| `cargo test` | Unit + integration tests |
| `cargo clippy --all-targets -- -D warnings` | Lint |
| `cargo fmt --check` | Format check |
| `dist plan --artifacts=all --tag=v0.4.0` | Release dry-run (cargo-dist 0.32) |
| `dist build --artifacts=all --tag=v0.4.0` | Build release artifacts (normally via CI) |

Release artifacts are built and published **only by CI** on tag push
(tag → GitHub Actions → GitHub Release); never publish them manually — see
`docs/release-process.md`.

## Architecture

- **One engine, one contract.** `ScanController` in `src/engine/` owns all
  scanning state; the API contract lives once in `src/api/types.rs`
  (`ScanConfig`, `Verdict`, `StopCondition`, events). CLI, wizard, HTTP server,
  and frontend are thin clients. The server maps engine types → API types;
  engine types are never serialized directly.
- **Phase 2 = Xray subprocess.** `xray run -c config.json` with a local socks
  inbound; fragment (DPI bypass) via a Freedom outbound + `sockopt.dialerProxy`
  chaining. The xray binary ships inside release archives (build-time
  download + `.dgst` SHA2-256 verification, feature `dist-bundle-xray`); dev
  builds fall back to a cached download in the data dir.
  Plain VLESS/Trojan combos (TCP transport, TLS or no TLS, fragmentation off)
  skip the subprocess entirely: the inline verifier speaks the wire protocol
  in-process, keeping those attempts in the low milliseconds instead of the
  ~50-200ms an xray spawn costs.
- **WARP probes.** boringtun builds a valid Init (MAC1 required, MAC2 zeros);
  a Response (92 B) or Cookie (64 B) of exact shape = open.
- **GeoIP.** db-ip.com Lite country MMDB embedded at build time
  (`include_bytes!` + maxminddb). Country is resolved offline per verdict.
  Data is CC BY 4.0 — attribution link in the UI footer.
- **Frontend.** One embedded HTML file (vanilla JS + native EventSource, zero
  build step), served by the same binary.

Design rationale lives in [docs/decisions/](docs/decisions/).

## Platform Caveats

- **Windows SmartScreen.** Release binaries are unsigned, so SmartScreen
  shows a warning. Accepted trade-off for a free tool; see
  [ADR-001](docs/decisions/ADR-001-xray-subprocess-and-bundling.md) for the
  equivalent trade-off on the bundled xray.
- **Termux (Android).** Termux builds static musl, but the xray
  linux-arm64 release is glibc — install Termux's glibc package or use the
  runtime fallback download instead of the bundled binary.
- **Offline builds.** Building requires network for the one-time GeoIP
  download: `build.rs` fetches the pinned `data/geoip-version.txt` release
  and verifies its SHA-256 — a failed download or checksum mismatch **fails
  the build** (no empty-db fallback). The validated database is cached in
  `target/**/out`, so repeat builds are offline after the first one until
  `cargo clean`. The xray bundle is only attempted for release builds, never
  dev builds. **Fully offline**: set `CFSCANNER_OFFLINE_BUILD=1` (any
  non-empty value) to skip the GeoIP download and checksum entirely and embed
  a placeholder instead — the build succeeds and country lookups simply
  return `None`. The flag never changes normal builds; unset it to embed the
  real database again.

## Security

- Binds to 127.0.0.1 only; the port is configurable with `--port`.
- Imported configs and keys are never logged or transmitted.
- Downloaded binaries are checksum-verified against pinned versions
  (`data/xray-version.txt`, `data/geoip-version.txt`).
- No history, no telemetry: results live in memory only; `reset` clears them.

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `serve` exits: port 8765 in use | Pick another port: `cf-scanner serve --port 9000` |
| Windows SmartScreen warning | Click "More info" → "Run anyway". Binaries are unsigned (accepted trade-off; see ADR-001). |
| Termux: phase-2 xray fails to start | Termux builds static musl; xray linux-arm64 is glibc — install Termux's glibc package. |
| Scan finds no results | Check network reachability, run `cf-scanner ranges refresh`, or try WARP mode / other ports. |

## Support & Contributing

Issues and feature requests:
<https://github.com/QMahyar/cf-scanner/issues>. Contributions are welcome:
open a PR from a fork, keeping `cargo test`, clippy `-D warnings`, and
`fmt --check` green (`docs/development.md`). Architecture decisions live in
`docs/decisions/`; the finished-product review (2026-08-13) is in
[docs/review/](docs/review/product-review-2026-08-13.md).

## Legal notice

Scanning Cloudflare's IP ranges with handshake probes may violate
Cloudflare's Terms of Service in some jurisdictions. The optional WARP
registration flow (`cf-scanner warp-config generate`, `src/warpgen.rs`)
calls Cloudflare's client registration API (`v0a884`) and sends the official
client's User-Agent (`okhttp/3.12.1`), impersonating the official app in the
wgcf style; that may also violate the Terms of Service. This tool is
provided for research and for use on networks you control. You are
responsible for complying with the laws and terms that apply where you run
it. Use at your own risk.

## License

MIT.

## Documentation

- `docs/README.md` — documentation index
- `docs/intent/cf-scanner.md` — confirmed user intent + verified research
- `docs/spec.md` — the approved spec
- `docs/development.md` — local build + test flow
- `docs/release-process.md` — versioning control + publishing pipeline
- `docs/decisions/` — architecture decision records
- `tasks/plan.md`, `tasks/todo.md` — implementation plan and task list
