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
  `--ipv6` opt-in and custom endpoint lists work.

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

## Recording results

Keep results in the issue tracker or a review notes file, including the
per-section "Record" items. Note the network profile — results that depend on
the network are not product bugs by themselves.