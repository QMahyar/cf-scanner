# Research: xray-core v26 vless+ws outbound → Cloudflare Workers timeout

Date: 2026-08-18
Context: phase-2 real-config verification generates an xray config from a vless URI
(`vless://…@104.16.3.119:443?…&type=ws&host=edgetunnel-3.qhulk1.workers.dev&path=/&packetEncoding=xudp`),
dials `104.16.3.149:443` (a Cloudflare anycast IP), then tunnels a probe to
`cp.cloudflare.com:443`. The log shows `tunneling request to tcp:cp.cloudflare.com:443
via 104.16.3.149:443` and then nothing. Plain TLS with the same SNI/Host via curl works
(0.7s, HTTP 200).

## TL;DR

The generated config is functionally valid for xray v26. `headers.Host` still works
(deprecated warning only), `packetEncoding` in `wsSettings` is silently ignored (it has
never been an xray field), and xray negotiates ALPN `http/1.1` for ws (same as curl).
None of those cause the timeout.

**Most likely root cause:** the probe target `cp.cloudflare.com:443` is hosted on
Cloudflare IPs, and **Cloudflare Workers are blocked from opening outbound TCP sockets
to Cloudflare IP ranges**. The edgetunnel worker's `connect()` to the probe target
fails/hangs, so it never sends the VLESS response header — xray waits forever. The
worker has a `retry()` → `PROXYIP` relay mechanism built exactly for this case; with
`PROXYIP` unset on the worker it reconnects to the same (blocked) target and hangs.
v2rayN "works" because normal browsing targets (e.g. google.com) are not on Cloudflare
IPs, so the worker can reach them.

## Q1. wsSettings format in v26.x — `host` vs `headers.Host`

**Answer:** both are honored in v26.x, but `headers.Host` is deprecated (startup
warning) and the modern form is the top-level `host` field.

- Official docs (current): `wsSettings = {acceptProxyProtocol, path, host, headers,
  heartbeatPeriod}`; host priority is `host` > `headers` > `address`.
  https://xtls.github.io/en/config/transports/websocket.html
- The independent `host` field was introduced on 2024-03-29 in commit `e2302b4`
  "Update proto file for websocket and httpupgrade (breaking)" (previously the proto
  had `reserved 1` and no host field; ws `Header` was a repeated key/value list).
  https://github.com/XTLS/Xray-core/commit/e2302b421c89195ea7b7a1f5389bae2e74623314
- v26.x source still explicitly migrates `headers.host` into `host` and prints
  `PrintDeprecatedFeatureWarning("host" in "headers", independent "host")`:
  `infra/conf/transport_method.go` (WebSocketConfig.Build) on `main` (v26.7.28).
  https://github.com/XTLS/Xray-core/blob/main/infra/conf/transport_method.go
- Users see the warning since at least 2025-04 (issue #4580):
  https://github.com/XTLS/Xray-core/issues/4580
- So **v26.3.27 still supports `headers.host`** (with warning). Recommended modern
  form:

```json
"wsSettings": {
  "path": "/",
  "host": "edgetunnel-3.qhulk1.workers.dev"
}
```

- Note: `WebSocketConfig` JSON struct is exactly `{host, path, headers,
  acceptProxyProtocol, heartbeatPeriod}` — anything else (e.g. `packetEncoding`) is
  ignored by Go's `json.Unmarshal` (no unknown-field error).

## Q2. packetEncoding

**Answer:** `packetEncoding` is **not** an xray config field anywhere in v26.x — not in
`wsSettings`, not in VLESS outbound settings, not in mux.

- Verified in source: ws `config.proto` on `main` (v26.7.28) = `{host, path, header,
  accept_proxy_protocol, ed, heartbeatPeriod}`; also v1.8.24 proto (same minus
  heartbeatPeriod) — **no packetEncoding ever**.
  https://raw.githubusercontent.com/XTLS/Xray-core/main/transport/internet/websocket/config.proto
- VLESS outbound JSON schema (`infra/conf/vless.go`): `{address, port, level, email,
  id, flow, seed, encryption, reverse, testpre, testseed, vnext}` — no packetEncoding.
  https://github.com/XTLS/Xray-core/blob/main/infra/conf/vless.go
- Mux object (docs): `{enabled, concurrency, xudpConcurrency, xudpProxyUDP443}` — no
  packetEncoding. https://xtls.github.io/en/config/outbound.html
- `"xudp-multi"` does not exist in xray (nor in sing-box). sing-box's VLESS
  `packet_encoding` accepts only `""`, `"packetaddr"`, `"xudp"`:
  https://sing-box.sagernet.org/configuration/outbound/vless/
- `packetEncoding=xudp` in a share URI is a client-side concept (v2rayN/Sagernet/
  sing-box model). It selects the UDP-over-stream encoding (XUDP = per-packet
  addressing) and only affects **UDP** proxying. **It cannot affect TCP-only traffic**,
  and in xray it is ignored entirely.

**Conclusion: not the cause. Safe to drop `packetEncoding` from the generated config.**

## Q3. ALPN with ws over TLS

**Answer:** xray forces `http/1.1` for WebSocket/HTTPUpgrade when `alpn` is unset —
it does **not** send `h2`.

- TLS docs: default ALPN is `["h2", "http/1.1"]`, but "For WebSocket and HttpUpgrade
  transports, `http/1.1` is used by default — otherwise negotiating to `h2` would
  prevent the connection from succeeding". This applies with uTLS fingerprints
  (`fingerprint: "chrome"`) too.
  https://xtls.github.io/en/config/transports/tls.html
- WebSocket docs confirm the trait: "ALPN is http/1.1".
  https://xtls.github.io/en/config/transports/websocket.html
- curl against the same IP uses http/1.1 by default, matching xray.

**Conclusion: ALPN is not the problem.** (Setting `alpn: ["h2","http/1.1"]` manually
would be the risky move.)

## Q4. Known issues: vless+ws / edgetunnel / Cloudflare

1. **Workers cannot reach Cloudflare IPs (the mechanism behind the timeout).**
   Official CF docs, current:
   - "Considerations: **Outbound TCP sockets to Cloudflare IP ranges are blocked.**"
   - Troubleshooting: `proxy request failed, cannot connect to the specified address`
     — "Your socket is connecting to an address that was disallowed. Examples of a
     disallowed address include **Cloudflare IPs**, localhost, and private network
     IPs."
   https://developers.cloudflare.com/workers/runtime-apis/tcp-sockets/
2. **edgetunnel's retry-to-PROXYIP exists precisely for CF-IP targets.** Worker code:
   if the remote socket produces no data (e.g. target is a CF IP), `retry()`
   reconnects via `proxyIP`; with an empty `PROXYIP` env it reconnects to the same
   target → hang. The VLESS response header is only sent together with the first
   remote data chunk, so the client sees exactly "nothing".
   - https://github.com/zizifn/edgetunnel/blob/main/src/worker-vless.js
   - zizifn issue #162 / proxyIP lists: https://github.com/zizifn/edgetunnel/issues/162
   - README note (ed-tunnel fork quoting CF docs): "Outbound TCP sockets to Cloudflare
     IP ranges are temporarily blocked"
     https://github.com/pegygood58/ed-tunnel
3. **XTLS discussion #5423** (2025-12): VLESS+WS+TLS through Cloudflare — direct
   connection works, via CF "connection established, but no data is transferred"
   (`OperationCanceled`). Unanswered.
   https://github.com/XTLS/Xray-core/discussions/5423
4. **WebSocket transport itself is deprecated** in favor of XHTTP (H2/H3); ws keeps
   working but emits a deprecation warning. Docs DANGER note + issue #4580.
5. Community reports of CF ws handshake failures across clients (e.g. 403 bad
   handshake): https://www.reddit.com/r/dumbclub/comments/1brk7s4/

## Q5. What modern v2rayN/v2rayNG generate for the same URI

v2rayNG (2dust, current master) — `CoreOutboundBuilder.kt`:
- ws: `wssetting.host = host`, `sni = host`, `wssetting.path = path ?: "/"`,
  `streamSettings.wsSettings = wssetting` — **top-level `host`, no packetEncoding**.
- tls: `tlsSettings {serverName, fingerprint, alpn(only if set in URI)}`.
- Since commit `7f0e2f8` (2026-05-25, PR #5686) it uses `host` instead of the
  deprecated `headers.Host`.
  https://github.com/2dust/v2rayNG/blob/master/V2rayNG/app/src/main/java/com/v2ray/ang/core/CoreOutboundBuilder.kt
  https://github.com/2dust/v2rayNG/commit/7f0e2f801d4cad483774748b0471c190df2cb2e1
- v2rayN desktop builds configs in the ServiceLib part of the same project family and
  mirrors this schema. For comparison, sing-box places `packet_encoding` on the VLESS
  outbound (not the transport) — sing-box docs (above).

Equivalent modern xray JSON for this URI:

```json
"streamSettings": {
  "network": "ws",
  "security": "tls",
  "tlsSettings": {
    "serverName": "edgetunnel-3.qhulk1.workers.dev",
    "fingerprint": "chrome"
  },
  "wsSettings": {
    "path": "/",
    "host": "edgetunnel-3.qhulk1.workers.dev"
  }
}
```

## Verifiable predictions (test before changing anything else)

1. Through the same tunnel, probe a **non-Cloudflare** target (e.g.
   `www.google.com:443` or `example.com:443`). If the tunnel works, the config is
   fine and the failure is the worker→CF-IP block, not xray.
2. Check the worker env for `PROXYIP`; without it, CF-hosted targets (like
   `cp.cloudflare.com`) cannot be dialed from the worker at all — for any client,
   including v2rayN.
3. Try the URI in v2rayN and probe `cp.cloudflare.com:443` specifically — expected to
   fail there too.

## Sources

- https://xtls.github.io/en/config/transports/websocket.html
- https://xtls.github.io/en/config/transports/tls.html
- https://github.com/XTLS/Xray-core/blob/main/infra/conf/transport_method.go
- https://raw.githubusercontent.com/XTLS/Xray-core/main/transport/internet/websocket/config.proto
- https://github.com/XTLS/Xray-core/commit/e2302b421c89195ea7b7a1f5389bae2e74623314
- https://github.com/XTLS/Xray-core/issues/4580
- https://github.com/XTLS/Xray-core/discussions/5423
- https://developers.cloudflare.com/workers/runtime-apis/tcp-sockets/
- https://github.com/zizifn/edgetunnel/blob/main/src/worker-vless.js
- https://github.com/zizifn/edgetunnel/issues/162
- https://github.com/2dust/v2rayNG/blob/master/V2rayNG/app/src/main/java/com/v2ray/ang/core/CoreOutboundBuilder.kt
- https://github.com/2dust/v2rayNG/commit/7f0e2f801d4cad483774748b0471c190df2cb2e1
- https://sing-box.sagernet.org/configuration/outbound/vless/
