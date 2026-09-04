# CF-Scanner

A single cross-platform Rust CLI that finds working Cloudflare IPs and
endpoints on ISP-restricted networks.

- **CDN/proxy mode.** Phase 1 runs a TCP+TLS handshake scan over official
  Cloudflare IPv4 ranges. Optional phase 2 verifies candidates against a
  real proxy config: VLESS/Trojan verify in-process, VMess/SS through an
  embedded Xray subprocess, with DPI-bypass fragmentation and SNI variants.
- **WARP mode.** UDP endpoint discovery over Cloudflare WARP pools with a
  real WireGuard handshake probe (boringtun). Optionally verify with your
  own WireGuard or AmneziaWG config, or register a config through
  Cloudflare's client API.

The CLI and an interactive wizard drive the same in-process engine. Results
are last-scan-only and live in memory. There is no history, no telemetry,
and nothing leaves your machine.

## Quick start

### Install

With Node >= 14.14 on any platform, install from npm. The wrapper downloads
the right binary from the GitHub Release and checks its SHA-256 against the
published checksum before extracting:

```sh
npm i -g @qmahyar/cf-scanner
```

Or download directly from the
[latest GitHub Release](https://github.com/QMahyar/cf-scanner/releases/latest):

- Windows: run the MSI installer. It upgrades in place. A portable zip also exists.
- Linux (x86_64 or aarch64): run the shell installer:

  ```sh
  curl -LsSf https://github.com/QMahyar/cf-scanner/releases/latest/download/cf-scanner-installer.sh | sh
  ```

- Any platform: extract the portable archive anywhere and run `cf-scanner`
  from there. No install step.

### Run

```sh
cf-scanner scan --mode cdn --preset quick
cf-scanner scan --mode cdn --preset quick --export results.csv --export-format csv
cf-scanner scan --mode warp --count 512
```

Results print as newline-delimited JSON on stdout; progress goes to stderr.
Pipe to `jq` for processing, or write an export file with `--export`
(`csv`, `json`, `base64`, `raw`, `singbox`, `clash`, `sharelinks`;
`-` writes to stdout). `sharelinks` rewrites your phase-2 config links onto
every passing endpoint, one URI per line.

### Build from source

```sh
cargo build --release
cargo run -- scan --mode cdn --preset quick
```

The Rust 2024 toolchain is required. See `docs/development.md` for the full
local flow. The first build needs network access for the one-time GeoIP
download. Set `CFSCANNER_OFFLINE_BUILD=1` to skip it (see
[Platform caveats](#platform-caveats)).

## Commands

With an installed binary, use `cf-scanner`. From source, replace
`cf-scanner` with `cargo run --`.

| Command | Description |
|---------|-------------|
| `cf-scanner scan --mode cdn --preset quick --target 20` | One-shot CDN scan; JSON lines print on stdout (`--target` alias `--stop-after`, `--cap` alias `--max-probes`) |
| `cf-scanner scan --mode warp --ports 2408,500` | One-shot WARP scan |
| `cf-scanner scan … --export out.csv --export-format csv` | Write results as `csv`, `json`, `base64`, `raw`, `singbox`, `clash`, or `sharelinks` (`-` = stdout) |
| `cf-scanner scan … --json-errors` | Print `{"error": …}` on stdout when the scan fails |
| `cf-scanner scan … --verbose` | Per-IP diagnostics on stderr (`203.0.113.5:443 — connection refused — loss 100%`, `203.0.113.1:443 — ok, 12ms — US/LAX`) plus info logs |
| `cf-scanner scan --mode cdn --probe http --colo HKG,NRT` | HTTP-trace probing (`tcp`/`tls`/`http`) keeping only listed colos; also `--loss-threshold`, `--min-latency`, `--idle-hold-ms`, `--neighbor-scan`, and opt-in `--speed-test`/`--min-speed` |
| `cf-scanner wizard` | Interactive wizard over the same engine |
| `cf-scanner warp-config generate` | Opt-in WARP registration through the v0a884 API, then wgconf build |
| `cf-scanner warp-config export` | Export the registered WARP config as text or a .conf file |
| `cf-scanner export-config --config vless://… --ip 1.2.3.4 --port 443` | Re-render a vless/trojan link against a scanned endpoint |
| `cf-scanner ranges refresh [--ipv6]` | Refresh bundled Cloudflare ranges over a verified HTTPS fetch (`--ipv6` includes the v6 pool) |
| `cargo test` | Unit + integration tests |
| `cargo clippy --all-targets -- -D warnings` | Lint |
| `cargo fmt --check` | Format check |
| `dist plan --tag=vX.Y.Z` | Release dry run (dist, formerly cargo-dist) |
| `dist build --artifacts=local --target=<host-target>` | Local release smoke test |

CI builds and publishes release artifacts on tag push only. Never publish
them manually; the pipeline is documented in `docs/release-process.md`.

## Architecture

- **One engine, one contract.** `ScanController` in `src/engine/` owns all
  scanning state. The contract lives once in `src/api/types.rs`
  (`ScanConfig`, `Verdict`, `StopCondition`, events). CLI and wizard are
  thin clients that consume those types directly.
- **Phase 2 runs Xray, except when it doesn't.** The subprocess form is
  `xray run -c config.json` with a local socks inbound. Fragment (DPI
  bypass) chains a Freedom outbound through `sockopt.dialerProxy`. Release
  archives bundle the xray binary, downloaded at build time and checked
  against its `.dgst` SHA2-256 (feature `dist-bundle-xray`). Dev builds fall
  back to a cached download in the data dir. Plain VLESS/Trojan combos (TCP
  transport, TLS or none, fragmentation off) skip the subprocess: the inline
  verifier speaks the wire protocol in-process, so those attempts finish in
  low milliseconds instead of the roughly 50 to 200 ms an xray spawn costs.
  `Phase2Verdict.verifier` reports which path verified each row. Multiple
  probe URLs share one keep-alive tunnel and must all return 200.
- **WARP probes.** boringtun builds a valid Init (MAC1 required, MAC2 may be
  zeros). A Response (92 B) or Cookie (64 B) of exact shape means open.
- **GeoIP.** The db-ip.com Lite country MMDB is embedded at build time with
  `include_bytes!` and read with maxminddb. Country resolution works
  offline. The data is CC BY 4.0; attribution link:
  <https://www.db-ip.com/>.

Design rationale lives in [docs/decisions/](docs/decisions/).

## Platform caveats

- **Windows SmartScreen.** Release binaries are unsigned, so SmartScreen
  shows a warning. This trade-off is accepted for a free tool; ADR-001
  documents the same trade-off for the bundled xray.
- **Termux (Android).** Termux builds static musl binaries, but the xray
  linux-arm64 release is glibc. Install Termux's glibc package, or let the
  runtime fallback download fetch a working binary instead of using the
  bundled one.
- **Offline builds.** The first build needs network for the GeoIP download:
  `build.rs` fetches the release pinned in `data/geoip-version.txt` and
  verifies its SHA-256. A failed download or checksum mismatch fails the
  build; there is no empty-database fallback. The validated database is
  cached in `target/**/out`, so later builds work offline until `cargo
  clean`. Only release builds attempt the xray bundle; dev builds never do.
  For a fully offline build, set `CFSCANNER_OFFLINE_BUILD=1`. Build.rs then
  skips the download and checksum and embeds a placeholder, so country
  lookups return `None`. Unset the flag to embed the real database again.

## Security

- Imported configs and keys are never logged or transmitted.
- Downloads are checksum-verified against pinned versions
  (`data/xray-version.txt`, `data/geoip-version.txt`). The npm wrapper
  re-verifies the archive SHA-256 at install time.
- No history, no telemetry. Results live in memory only.

## Troubleshooting

| Problem | Fix |
|---------|-----|
| Windows SmartScreen warning | Click **More info**, then **Run anyway**. Binaries are unsigned; see ADR-001. |
| Termux: phase-2 xray fails to start | Termux builds static musl; xray linux-arm64 is glibc. Install Termux's glibc package. |
| Scan finds no results | Check network reachability, run `cf-scanner ranges refresh`, or try WARP mode or other ports. |

## Support and contributing

Report issues and feature requests at
<https://github.com/QMahyar/cf-scanner/issues>. Contributions are welcome.
Open a PR from a fork and keep `cargo test`, clippy `-D warnings`, and
`fmt --check` green (`docs/development.md`). Architecture decisions live in
`docs/decisions/`.

## Legal notice

Scanning Cloudflare's IP ranges with handshake probes may violate Cloudflare's
Terms of Service in some jurisdictions. The optional WARP registration flow
(`cf-scanner warp-config generate`, `src/warpgen.rs`) calls Cloudflare's
client registration API (`v0a884`) and sends the official client's User-Agent
(`okhttp/3.12.1`), impersonating the official app in the wgcf style. That
may also violate the Terms of Service. This tool is provided for research and
for use on networks you control. You are responsible for complying with the
laws and terms that apply where you run it. Use at your own risk.

## License

MIT.

## Documentation

- `docs/README.md`: documentation index
- `CONTEXT.md`: context map with module index and domain glossary
- `docs/intent/cf-scanner.md`: confirmed user intent and research corrections
- `docs/spec.md`: the approved spec
- `docs/development.md`: local build and test flow
