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
published checksum before extracting. The npm binaries are glibc-linked
(Debian/Ubuntu/Fedora/Arch work out of the box); musl/Alpine needs a glibc
container.

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
(`csv`, `json`, `base64`, `raw`, `singbox`, `clash`, `sharelinks`,
`v2ray`, `shadowrocket`, `quantumult`;
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
`cf-scanner` with `cargo run --`. Every flag below is documented in
`--help` (run `cf-scanner scan --help` for the full reference).

### `scan`

The main command. Phase 1 probes candidates; phase 2 (opt-in) verifies
them through a real proxy config.

**Candidate selection**

| Flag | Meaning |
|------|---------|
| `--mode cdn\|warp` | `cdn` probes Cloudflare ranges for working proxies (default); `warp` discovers usable WARP UDP endpoints |
| `--preset quick\|normal\|full` | Sized CDN sweep of the official ranges: `quick` = 1 IP per /24, `normal` = 3 per /24, `full` = every usable host. Conflicts with `--count` |
| `--count N` | Probe N random candidates from the ranges instead of a preset |
| `--ports 443,2053` | TCP ports to probe (CDN default 443; WARP default 2408,500,1701,4500) |
| `--exclude CIDR,…` | CIDR blocks to skip (e.g. `10.0.0.0/8,192.168.0.0/16`) |
| `--custom-cidrs CIDR,…` | Scan only these blocks instead of the official ranges |
| `--ipv6` | Include the IPv6 range pool (CDN only; WARP pools are IPv4) |
| `--colo HKG,NRT` | Keep only phase-2 results from these Cloudflare colos (IATA codes) |

**Stopping**

| Flag | Meaning |
|------|---------|
| `--target N` (alias `--stop-after`) | Stop as soon as N endpoints are found (default 20) |
| `--cap N` (alias `--max-probes`) | Hard probe-count ceiling: stop after N probes, found or not |

`--target` is the goal, `--cap` the budget. Whichever hits first ends the
scan; results up to that point are kept.

**Tuning**

| Flag | Meaning |
|------|---------|
| `--concurrency N` | Parallel probe workers (default 256, max 1000) |
| `--timeout-ms MS` | Per-probe timeout (default 3000) |
| `--probe tcp\|tls\|http` | Phase-1 protocol: connect only, TLS handshake (default), or GET `/cdn-cgi/trace` over TLS |
| `--http-status-code 200,204` | HTTP probe mode: codes that count as working (default 200,301,302; requires `--probe http`) |
| `--loss-threshold PCT` | Drop results whose packet-loss rate exceeds PCT (0-100) |
| `--min-latency MS` | Drop results whose handshake latency is *below* MS — throttled routes look fast but stall; use this to filter them, not to demand fast IPs |
| `--idle-hold-ms MS` | After the TLS handshake, hold the connection idle for MS and fail the probe if it is reset (0 = off) |
| `--neighbor-scan N` | After a hit, probe up to N neighboring IPs in the same /24 (0-64, CDN only) |
| `--seed N` | Deterministic RNG for `--count` sampling and neighbor probes (same seed = same plan) |
| `--enrich-asn` | After the scan, look up ASN/ISP per working endpoint via ipwho.is and annotate exported results (best-effort) |

**Phase 2 (xray verification)**

| Flag | Meaning |
|------|---------|
| `--phase2-configs URI,…` | Share URIs (vless/vmess/trojan/ss) to verify candidates against; enables phase 2 |
| `--phase2-fragment off\|light\|medium\|heavy\|custom` | DPI-bypass fragmentation. Values are TLS-hello fragment length/interval: `light` 100-200/10-20, `medium` 50-200/10-40, `heavy` 10-300/5-50 |
| `--phase2-custom packets,length,interval` | Custom fragment values, e.g. `1-3,10-20,10-20`; requires `--phase2-fragment custom` |
| `--phase2-snis SNI,…` | SNI values to try per config (first that verifies wins) |
| `--phase2-probe-urls URL,…` | HTTPS URLs fetched through the tunnel to confirm it works; default is the built-in trace check. When set, this list takes precedence over the built-in single URL |
| `--phase2-concurrency N` | Parallel verifications (default 4, max 8) |
| `--speed-test` | After verification, download an 8 MiB sample through each verified endpoint and record MB/s (CDN only) |
| `--min-speed MBPS` | Drop endpoints measuring below MB/s (requires `--speed-test`) |

**WARP**

| Flag | Meaning |
|------|---------|
| `--warp-endpoints IP:PORT,…` | Scan these endpoints instead of the bundled WARP pools |
| `--warp-probes N` | WireGuard handshake attempts per endpoint (default 3, max 10) |
| `--warp-verify` | After discovery, complete a full WireGuard handshake using your config (proves usable, not just reachable; requires `--warp-wgconf-file`) |
| `--warp-wgconf-file PATH` | WireGuard/AmneziaWG `.conf` used for `--warp-verify` (the file stays local; the key is never logged) |

**Export and misc**

| Flag | Meaning |
|------|---------|
| `--export FILE` | Write results to this file when the scan ends (`-` = stdout) |
| `--export-format FMT` | `csv`, `json`, `base64`, `raw`, `singbox`, `clash`, `sharelinks`, `v2ray`, `shadowrocket`, `quantumult` (default `csv`) |
| `--retry-last` | Replay the last scan's saved configuration (saved after each scan; phase-2 configs and WARP keys are never saved — re-supply those) |
| `--json-errors` | Print `{"error": …}` on stdout when the program fails (for scripts) |
| `--verbose` | Per-IP diagnostics on stderr plus info logs |

### Other subcommands

| Command | Description |
|---------|-------------|
| `cf-scanner wizard` | Interactive wizard over the same engine |
| `cf-scanner ranges refresh [--ipv6]` | Refresh the bundled Cloudflare range lists over a verified HTTPS fetch (`--ipv6` includes the v6 pool) |
| `cf-scanner check-sub URL [--timeout-ms MS]` | Fetch a subscription and verify every config against its own server; one NDJSON row per config (`ok`/`latency_ms`/`error`), a summary on stderr, non-zero exit when nothing verifies |
| `cf-scanner warp-config generate [--license KEY] [--endpoint HOST:PORT] [--out FILE]` | Opt-in WARP registration through the v0a884 API, then wgconf build. Without `--out` the wgconf prints to stdout; a `.conf` path is written with owner-only permissions |
| `cf-scanner warp-config export [--endpoint HOST:PORT] [--out FILE]` | Export the registered WARP config as text or a .conf file |
| `cf-scanner export-config --config URI --ip IP --port PORT [--sni SNI]` | Re-render a vless/vmess/trojan/ss link against a scanned endpoint; `--sni` overrides the TLS SNI in the output |
| `cargo test` / `cargo clippy --all-targets -- -D warnings` / `cargo fmt --check` | Unit + integration tests, lint, format check |
| `dist plan --tag=vX.Y.Z` | Release dry run (dist, formerly cargo-dist) |
| `dist build --artifacts=local --target=<host-target>` | Local release smoke test |

CI builds and publishes release artifacts on tag push only. Never publish
them manually; the pipeline is documented in `docs/release-process.md`.

### Key workflows

Sweep, verify, and export a ready-to-import bundle:

```sh
cf-scanner scan --preset normal \
  --phase2-configs "vless://UUID@host:443?security=tls" \
  --phase2-fragment medium \
  --target 5 --cap 100000 \
  --export bundle.txt --export-format sharelinks
```

Re-run yesterday's scan with fresh keys (the saved config keeps everything
except secrets):

```sh
cf-scanner scan --retry-last \
  --phase2-configs "vless://UUID@host:443?security=tls"
```

Verify a WARP pool and prove a full handshake works with your own config:

```sh
cf-scanner scan --mode warp --warp-verify --warp-wgconf-file warp.conf
```

Speed-rank verified endpoints and keep only the fast ones:

```sh
cf-scanner scan --preset quick \
  --phase2-configs "vless://UUID@host:443" \
  --speed-test --min-speed 2 \
  --export fast.csv
```

Scripted use — JSON lines on stdout, JSON error envelope on failure:

```sh
cf-scanner scan --count 100 --json-errors \
  | jq 'select(.ip != null) | [.ip, .port, .latency_ms]'
```

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
- **Termux (Android).** The CI static builds are musl; the xray helper is
  glibc. Step by step:
  1. Install the binary from the GitHub Release (the portable
     `x86_64-unknown-linux-musl` tarball runs natively under Termux).
  2. Give phase-2 a glibc runtime: `pkg install glibc-runner` and run the
     binary through it (`termux-fix-shebang` not needed; use
     `glibc-runner ./cf-scanner …`), or install Termux's `glibc` package
     per its wiki.
  3. Grant storage once: `termux-setup-storage`, and keep the data dir on
     local storage (CF_SCANNER_DATA_DIR) so trial configs are writable.
  4. WARP mode needs a real WireGuard UDP path — some mobile networks
     block it; use CDN mode if endpoints never answer.
  The runtime download fallback can also fetch a working xray itself if
  the bundled one will not start.
- **Docker/musl images.** The npm binaries are glibc-linked. On Alpine use
  a glibc base (e.g. `debian:slim` or the `gcompat` layer) or the
  standalone `x86_64-unknown-linux-musl` archive from GitHub Releases
  (see also the T-35 musl proposal for native musl npm support).
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
| Phase 2: "no verified xray binary" | Re-run the scan; the runtime re-downloads xray from the pinned GitHub release and checks its SHA-256. Behind a blocked proxy, download the archive manually into the data dir (the path is printed in the error). |
| Phase 2: everything fails with handshake errors | Try `--phase2-fragment medium` (DPI bypass), then `--phase2-fragment heavy`. Try `--phase2-snis` with a fronting domain your ISP allows. |
| WARP mode finds no results | WARP is UDP; some networks block it entirely. Try `--ports 2408,500,1701,4500`, or `--warp-probes 10`. If nothing answers, the network blocks WireGuard — use CDN mode. |
| Scan finds no results | Check network reachability, run `cf-scanner ranges refresh`, or try WARP mode or other ports. |
| Ranges refresh fails | The refresh fetches `api.cloudflare.com/client/v4/ips` over HTTPS with SSRF guards. If it fails, the scan keeps the bundled (possibly older) list and warns once. Automate refreshes — see `docs/refresh-automation.md` (cron/systemd/Task Scheduler/Termux). |

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
- `docs/refresh-automation.md`: keeping the Cloudflare range lists current
- `CONTEXT.md`: context map with module index and domain glossary
- `docs/intent/cf-scanner.md`: confirmed user intent and research corrections
- `docs/spec.md`: the approved spec
- `docs/development.md`: local build and test flow
