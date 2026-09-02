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

1. Run a CDN scan with phase 2 enabled and a real config:
   `cf-scanner scan --mode cdn --preset quick --phase2-configs <vless://|trojan://|vmess://|ss:// URI or subscription URL or Xray JSON>`.
2. Alternatively drive the same path interactively:
   `cf-scanner wizard` (CDN mode → phase 2 → config import → run).

Expected outcomes:

- Phase-1 candidates appear live on stderr; phase-2 passes report a verdict
  with the fragment preset and SNI that worked, plus tunnel latency.
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
- Every result row must show loss **0%** — an endpoint with any probe loss is
  excluded from results (working = open AND zero probe loss).

Record: probe count, open count (e.g. "183/204 open"), ports that answered,
latency ranges, wall time.

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

- Verified HTTPS fetch succeeds; the refreshed file updates with a new
  `last_updated` timestamp (also printed by `cf-scanner ranges refresh`).

Record: subnet counts before/after (15 IPv4 + v6 list), `last_updated`,
verification failures if any.

## 5. Export to file (manual)

- `cf-scanner scan --mode cdn --preset quick --export out.csv --export-format csv`
  writes the results CSV; `--export-format json` the metadata dump. With
  phase-2 configs, `--export-format base64|raw|singbox|clash` writes proxy
  bundles whose links point at the scanned IP:port.
- `--export -` prints the same payload to stdout instead of a file.
- Invalid `--export-format` without `--export`-compatible usage must exit
  nonzero with a clear error.

Record: file created, row counts vs scan summary, bundle import into a proxy
client, stdout round trip.

## 6. Phase-2 export + inline verifier (manual)

Requires at least one real VLESS or Trojan config (own server). Use the
smallest scan that produces results (custom count 50-100, stop-after 1-3).

- **Inline verifier (hot path).** Run a phase-2 scan with a plain vless
  `vless://<uuid>@<host>:<port>?security=tls&sni=<host>` config, fragment
  off. Every phase-2 row must show `verifier: "inline"` in the NDJSON
  output — i.e. no `xray run` in the log. Repeat with a Trojan config; rows
  must show `verifier: "inline"` again. Then add fragmentation (any preset)
  and re-run: rows must show `verifier: "xray"` and the xray subprocess must
  appear.
- **Export round trip.** Run the scan with
  `--export sub.txt --export-format base64`: the exported link must point
  at the scanned IP:port with the original scheme/uuid/query intact (SNI
  overridden to the row's SNI when one was used). Same result via the CLI:
  `cf-scanner export-config --config "vless://…" --ip <ip> --port <port>`.
  Then import the exported link into your client and verify it connects.
- **Multiple probe URLs.** Add `--phase2-probe-urls` and verify all URLs are
  fetched over a single tunnel: one xray spawn serves every URL (inline
  mode: one connection). A candidate must fail the whole row when any URL
  does not return 200.

Record: `verifier` values per config type, exported-link exactness (diff
against the original URI), connect result after import, spawn counts.

## Recording results

Keep results in the issue tracker or a review notes file, including the
per-section "Record" items. Note the network profile — results that depend on
the network are not product bugs by themselves.