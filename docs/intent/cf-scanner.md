# CF-Scanner — Confirmed Intent

Date: 2026-08-12
Status: Confirmed by user (interview-me skill)

## Summary

One cross-platform Rust binary that finds working Cloudflare IPs/endpoints for
restricted networks. Two modes (CDN/proxy and WARP), one local API, an embedded
browser frontend, and an agent-friendly CLI — all driving the same engine.

## The Five Lines

- **Outcome:** A single binary that scans Cloudflare IPv4s (phase 1: TCP/TLS
  handshake; phase 2: real-config verification via embedded xray-core) and WARP
  UDP endpoints, reporting country/datacenter/latency/packet-loss per result.
- **User:** Two audiences — CLI agents (JSON API + flags/wizard) and normal
  users (browser frontend with a clean, fast, sortable results list).
- **Why now:** The user's ISP blocks/throttles Cloudflare IPs selectively;
  finding working IPs by hand is slow and time-sensitive.
- **Success:** User picks mode/phase, IP count, stop condition via wizard, flags,
  or browser; results appear live; copy/save/reset supported; agents can script
  the entire flow over the local API.
- **Constraint:** Single binary, IPv4 only, localhost only, no history (last
  scan + reset), configs never leave the machine, no telemetry, no speed tests.

## Detailed Intent (verbatim decisions)

### Runtime
- Single binary. Starts local HTTP server on `127.0.0.1` (localhost only).
- REST + live-events (SSE) API + embedded web frontend.
- Always offers to open the browser; prints URL/port.
- CLI flags/subcommands + interactive wizard drive the same in-process API as
  the browser UI.
- No history: last scan only; reset button clears memory. No telemetry.

### CDN/proxy mode
- Phase 1: TCP+TLS handshake scan over bundled official Cloudflare ranges
  (14 IPv4 subnets, ~1.5M IPs). `refresh` command re-fetches from Cloudflare.
  Custom CIDR input. Per-scan dirty-range exclusion list.
  Presets: Quick (1 IP per /24) / Normal (~12K) / Full (~1.5M) + custom count.
  Ports configurable, default 443. Fast concurrency defaults, configurable.
  Latency per IP only (no loss column in phase 1).
  Stop-after-N working IPs + optional cap (count or time); "don't stop" = no
  cap until N found.
- Phase 2 (optional): import configs via `vless://` / `trojan://` / `vmess://` /
  `ss://` URIs, subscription URLs, or Xray JSON configs.
  Embedded xray-core (real engine). Swap candidate IP into config, launch,
  tiny HTTP request (configurable target) through the local proxy → HTTP 200 =
  pass; latency measured on tunnel.
  Per-IP verdict records the fragment preset (light/medium/heavy + custom
  params) and SNI combo that worked (SNI fronting variants).
  NO download/speed tests (user explicit: data- and time-hungry).

### WARP mode (separate settings from CDN mode)
- Candidate endpoints from known pools: `8.47.69.0/24`, `162.159.192.0/24`,
  `162.159.193.0/24`, `162.159.195.0/24`, `188.114.96.0/24`–`188.114.99.0/24`.
  Ports configurable, default 2408 (+ 500/854/880/1701/3138/4500 etc.).
  Custom endpoint list input allowed.
- Discovery: dummy-key WireGuard handshake probe; Response/Cookie packet = open;
  latency + loss % (N probes) reported.
- Optional: user's real wgconf (WireGuard/AmneziaWG) pasted as text or file →
  real handshake with their keypair = verified with THEIR config.
- Opt-in only ("generate a WARP config for me"): local Curve25519 keygen →
  register via `api.cloudflareclient.com/v0a884` (POST /reg, PATCH
  warp_enabled, GET config) → auto-import → scan endpoints → export final
  config as plain text or `.conf` file. Optional WARP+ license binding.
  Identity persisted locally (wgcf-style). No proxy fallback for registration.

### Results
- Last scan only. Columns: IP:port | country | datacenter (colo) | latency |
  loss (WARP/phase-2 only). Sortable by latency (default), country, datacenter,
  loss. Phase 2 adds verdict + fragment/SNI combo detail.
- Country: bundled offline mmdb (IP2Location LITE, free redistributable).
  Datacenter: colo code via `/cdn-cgi/trace` (phase 2); phase 1 country-only.
- Copy with ports (ip:port per line) or raw IPs (per line); no leading/trailing
  whitespace; newline-separated. Save (file download). Reset.

### Stack (confirmed)
- Rust 2024, tokio, clap, serde, axum, tokio-rustls, reqwest,
  x25519-dalek + chacha20poly1305 + blake2 (WireGuard handshake),
  maxminddb (IP2Location LITE mmdb), tracing, xray-core crate (embedded Xray).
- Frontend: vanilla HTML + htmx + SSE + Pico.css, embedded, zero build step.

### Release pipeline (confirmed)
- Public GitHub repo, MIT license. Name: CF-Scanner / cf-scanner.
- GitHub Actions + cargo-dist. PR checks (test/clippy/fmt).
- Tag → matrix build → GitHub Release with checksums + installers
  (MSI for Windows, brew for macOS, shell for Linux).
- Target matrix (5): windows-x86_64, linux-x86_64 (Debian/Fedora/Arch),
  linux-aarch64 (Termux, static musl), macos-x86_64, macos-aarch64.
- Caveat: xray-core has no official windows-arm64 build (not in matrix anyway).
  Termux: xray bundling uses linux-arm64 glibc binary (needs Termux glibc pkg).
- Unsigned binaries → Windows SmartScreen warning (accepted, ecosystem norm).
- Semver tags + changelog.

### Out of scope
- IPv6, download/speed tests, scan history, cloud backend, config sharing,
  mobile apps, GUI framework (browser is the UI), registration proxy fallback,
  code signing.

## Technical Corrections (source-verified 2026-08-12)

Changes to the confirmed intent above, grounded in official sources. User
decision required where marked **[DECISION]**.

1. **xray-core crate is NOT a binary embedder.** crates.io `xray-core` (0.2.1)
   is a gRPC *client* for an already-running Xray (docs.rs). No official Rust
   API launches Xray in-process (only XTLS/libXray via C). => We spawn the real
   `xray` binary as a subprocess (`xray run -c config.json`) with a local
   socks/http inbound. **[DECISION]** Binary delivery: (a) auto-download from
   GitHub releases at first phase-2 use with `.dgst` checksum verification,
   cached in the data dir, or (b) bundle into release archives via dist
   ExtraArtifact. Recommendation: (a) runtime download + cache, with (b) as a
   later optimization.
   Sources: https://docs.rs/crate/xray-core/latest,
   https://github.com/XTLS/Xray-core/releases (asset naming `Xray-<os>-<arch>.zip`).

2. **Xray platform coverage (v26.3.27):** windows-amd64 + windows-arm64,
   linux-amd64 + linux-arm64, macos-amd64 + macos-arm64 all exist. Full 5-target
   matrix can bundle xray.

3. **Fragment config (XTLS docs, current):** `fragment` lives on a Freedom
   outbound (`"fragment": {"packets": "tlshello", "length": "100-200",
   "interval": "10-20"}` — Int32Range strings); `dialerProxy` lives in
   `streamSettings.sockopt` of the proxied outbound (chains to the fragment
   freedom outbound). Presets: light 100-200/10-20, medium 50-200/10-40,
   heavy 10-300/5-50 (community, cfray). Custom = user-supplied
   packets/length/interval.
   Sources: https://xtls.github.io/en/config/outbounds/freedom.html,
   https://xtls.github.io/en/config/transports/sockopt.html

4. **WireGuard probe (wireguard.com/protocol + wireguard-go):** Init = 148 B
   (MAC1 mandatory — key `HASH("mac1----"||server_pub)` is public-constant;
   MAC2 zeros fine), Response = 92 B, Cookie Reply = 64 B. A valid Init is
   required to elicit ANY reply. Dummy-key probes work against WARP because
   Cloudflare answers handshakes for arbitrary client keys (empirical,
   wgcf-ecosystem norm). Use the **boringtun** crate (Cloudflare, maintained)
   to build Init with valid MAC1 and parse replies — no hand-rolled crypto.
   WARP server public key: bundle the known constant, refresh from the
   registration API when available. Open = Response (type 2, len 92) or
   Cookie (type 3, len 64), structurally valid — CORRECTION (verified live
   2026-08-13 against real WARP): the receiver index in replies does NOT
   match the Init's sender index for dummy-key probes (Cloudflare answers
   under its own session index; wgcf-ecosystem scanners classify on packet
   shape alone). Index matching would mark every real endpoint closed.
   Sources: https://www.wireguard.com/protocol/, https://docs.rs/boringtun/

5. **GeoIP: switch to db-ip.com Lite MMDB.** IP2Location LITE ships CSV/BIN
   only — the maxminddb crate (0.30, ISC) reads MMDB only. db-ip.com Lite
   (IP-to-Country + City) ships MMDB, CC BY 4.0, free, monthly updates.
   Embed via `include_bytes!` + `Reader::from_source`. Attribution link in UI.
   Sources: https://db-ip.com/db/lite.php, https://docs.rs/maxminddb

6. **Release tooling: dist (formerly cargo-dist) v0.31.** `dist init
   --ci=github` writes `[workspace.metadata.dist]` (targets, installers,
   cargo-dist-version), generates release.yml (plan/build/host/publish).
   Installers: shell + powershell (global), msi (local). `ExtraArtifact`
   config exists for bundling extra files (mmdb) alongside tarballs. Install on
   Arch: `pacman -S cargo-dist`. Mac pkg via MacPkgConfig.
   Sources: https://axodotdev.github.io/cargo-dist/,
   https://docs.rs/cargo-dist/latest/cargo_dist/config/index.html

7. **Frontend verified:** htmx SSE via the `htmx-ext-sse` extension
   (`hx-ext="sse"`, `sse-connect`, `sse-swap`), v2.2.4. Pico.css v2.1.1, MIT,
   zero deps, vendorable. `/cdn-cgi/trace` is unofficial but live-verified:
   plain `key=value` lines with `colo` (3-letter datacenter code).
   Sources: https://htmx.org/extensions/sse/, https://picocss.com
