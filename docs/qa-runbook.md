# CF-Scanner — Manual QA Runbook (live verification)

Manual, network-touching verification — the counterpart to the "no automated
live evidence in CI" gap from the [finished-product
review](review/product-review-2026-08-13.md) (Domain 2). Run against a real
network; record what each section asks for. Failures are bugs only if they
reproduce on a clean network profile — note the profile in the report.

## Before you start

- Built binary: `cargo build --release`, or an installed release binary.
- Live network; these tests deliberately hit real Cloudflare endpoints.
- Diagnostics: `RUST_LOG=info cf-scanner <cmd>` for detailed logs.
- Record per run: date, binary version, OS, network profile (ISP/country),
  and the items listed under "Record" in each section.

## 1. Phase-2 scan against the bundled xray

1. `cf-scanner serve` and open http://127.0.0.1:8765.
2. Start a CDN scan (Quick preset) with phase 2 enabled and a real config:
   paste a `vless://` / `trojan://` / `vmess://` / `ss://` URI, a subscription
   URL, or an Xray JSON config in the phase-2 form.
3. Alternatively drive the same path interactively:
   `cf-scanner wizard` (CDN mode → phase 2 → config import → run).

Expected outcomes:

- Phase-1 candidates appear live; phase-2 passes report a verdict with the
  fragment preset and SNI that worked, plus tunnel latency.
- The xray subprocess comes from the bundled binary (pinned in
  `data/xray-version.txt`, `.dgst`-verified) or a checksum-verified fallback
  download; no xray process remains after the scan ends.

Record: phase-2 pass count + latencies, fragment preset + SNI per pass, xray
version used, download/checksum events, wall time per phase.

## 2. WARP handshake probe

```
cf-scanner scan --mode warp --ports 2408,500
```

Expected outcomes:

- Open endpoints (Response/Cookie packet shape) with latency + loss %;
  custom endpoint lists (`--warp-endpoints`) work. (`--ipv6` is CDN-only —
  the CLI rejects it for WARP; see `src/main.rs`.)

Record: probe count, open count (e.g. "183/204 open"), ports that answered,
loss/latency ranges, wall time.

## 3. Registration via `warp-config generate --license`

1. `cf-scanner warp-config generate` (add `--license <WARP+ license>` to
   bind WARP+; optional).
2. `cf-scanner warp-config export` → text / `.conf` file.
3. Verify the generated config: run a WARP scan with the wgconf and confirm a
   real WireGuard handshake with the registered keypair.

Expected outcomes:

- Identity registered via `api.cloudflareclient.com/v0a884` (register →
  PATCH warp_enabled → GET config); valid wgconf generated and exported; the
  scan engine completes a real handshake with the registered keypair.

Record: registration response fields, identity file location, exported config
validity, handshake success + endpoint.

## 4. Ranges refresh

```
cf-scanner ranges refresh
```

Expected outcomes:

- Verified HTTPS fetch succeeds; ranges update with a new `last_updated`
  timestamp (visible in the UI and `GET /api/ranges`).

Record: subnet counts before/after (15 IPv4 + v6 list), `last_updated`,
verification failures if any.

## 5. Tray / autostart (Windows, manual)

Requires a desktop session (logged-on user with a notification area).

- `cf-scanner serve --tray` → the CF-Scanner icon appears in the notification
  area (orange circle) and the server keeps running; the terminal is not
  required afterwards.
- Menu items: "Open UI" opens the browser at the served URL; "Start CDN scan"
  starts a quick-preset CDN scan and "Start WARP scan" a 40-endpoint WARP
  scan (both visible/controllable in the UI); "Cancel" stops the running
  scan.
- "Exit" shuts `serve` down gracefully: the server stops, no tray icon
  remains, the process exits. (Ctrl+C still works the same with `--tray`.)
- `cf-scanner serve --tray --autostart` prints the registry location and
  writes `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\CF-Scanner`;
  verify in `regedit` (a `REG_SZ` of `"<exe>" serve --tray`). Reboot → the
  app starts in the tray with the UI ready.
- Cleanup check: deleting the `CF-Scanner` Run value (manual, registry
  editor) must leave the server unaffected, and `serve --tray` must still
  warn-and-continue when started in a headless session.
- Non-Windows: `serve --tray` prints "tray not supported on this platform;
  serving without it" and keeps serving normally.

Record: icon appearance, each menu item's effect, Exit shutdown, regedit
value string, reboot result, headless-session behavior.

## 6. Phase-2 export + inline verifier (manual)

Requires at least one real VLESS or Trojan config (own server). Use the
smallest scan that produces results (custom count 50-100, stop-after 1-3).

- **Inline verifier (hot path).** Run a phase-2 scan with a plain vless
  `vless://<uuid>@<host>:<port>?security=tls&sni=<host>` config, fragment
  off. Every phase-2 row must show `verifier: "inline"` in the API
  (`GET /api/results`) — i.e. no `xray run` in the log. Repeat with a
  Trojan config; rows must show `verifier: "inline"` again. Then add
  fragmentation (any preset) and re-run: rows must show `verifier: "xray"`
  and the xray subprocess must appear.
- **Export round trip.** In the UI, click Export on a verified row → the
  exported link must point at the scanned IP:port with the original
  scheme/uuid/query intact (SNI overridden to the row's SNI when one was
  used). Same result via the CLI:
  `cf-scanner export-config --config "vless://…" --ip <ip> --port <port>`
  and via `POST /api/config/export` with a JSON body. Then import the
  exported link into your client and verify it connects.
- **Multiple probe URLs.** Add `--phase2-probe-urls` (one URL per line in
  the UI textarea) and verify all URLs are fetched over a single tunnel:
  one xray spawn serves every URL (inline mode: one connection). A
  candidate must fail the whole row when any URL does not return 200.

Record: `verifier` values per config type, exported-link exactness (diff
against the original URI), connect result after import, spawn counts.

## Recording results

Keep results in the issue tracker or a review notes file, including the
per-section "Record" items. Note the network profile — results that depend on
the network are not product bugs by themselves.