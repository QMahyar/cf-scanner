---
name: Probe/WARP panic path + verify-layer hardening
labels: [wayfinder:task]
state: closed
assignee: ox-alpha
branch: review/probe
blocked-by: []
---

## Question

Findings across `src/warp.rs`, `src/warpgen.rs`, `src/inline_verify.rs`,
`src/socks.rs`, `src/ranges.rs` on a `review/probe` branch.

1. **Reachable panic from corrupt identity** — `warp.rs:45-48` `expect()`s on
   the persisted `peer_public_key`; `warpgen.rs:285-290` returns any non-empty
   string unvalidated. Fix inside `persisted_server_public_key`: base64-decode +
   32-byte check, fall back to the bundled constant otherwise (the comment at
   `warp.rs:41-42` already promises silent fallback). Test: corrupt
   `peer_public_key` in an identity file → probe uses bundled key, no panic.
2. **Remove `loss_pct` from WARP verdicts — APPROVED CONTRACT CHANGE** —
   always 0.0 by zero-loss gating (`warp.rs:166-172`); remove the field from the
   API type + wire + tests (decided; do not emit lossy verdicts instead).
3. **64 MiB preallocation from hostile headers** — `inline_verify.rs:554,580`:
   `vec![0u8; size]` trusts Content-Length/chunk size up to MAX_BODY_BYTES.
   The probe only needs a tiny trace body: drop the effective body cap to
   something probe-shaped (e.g. 1 MiB) OR stream-read; either way no single
   hostile header can force a 64 MiB zeroed alloc. Keep socks.rs's 64 MiB
   reader cap as-is except item 4.
4. **send_http silent truncation → explicit failure (DECIDED)** —
   `socks.rs:40-51`: when the `.take()` limit is hit, return an explicit
   "response body exceeded cap" error instead of breaking at EOF. Proptest for
   the boundary.
5. **tls_connector rebuilt per call** — `socks.rs:112-119`: build the
   `TlsConnector` once (OnceLock/LazyLock static); hot path calls it per probe.
6. **fetch_one mangles IPv6-literal URLs** — `ranges.rs:630`
   `rsplit_once(':')` breaks `[2606:4700::1]:443`. Parse bracketed hosts
   properly (strip brackets, split port outside them); test with a v6-literal
   https URL through `validate_fetch_url`.

Acceptance: verification trio green; no new unwrap/expect on external data.

## Resolution

Fixed on eview/probe (worktree cfs-wt-probe), commit 0b92b7. All six
items: persisted key validated via wgconf::decode_key with fallback to the
bundled constant (test corrupt_persisted_public_key_degrades_to_none);
loss_pct removed across api/types.rs, engine/warp.rs, cdn.rs, phase2.rs,
main.rs and embed/index.html table + CSV export; inline_verify now allocates
against MAX_PROBE_BODY_BYTES=1MiB; send_http returns an explicit over-cap
error (test send_http_fails_explicitly_past_the_body_cap via duplex stream);
tls_connector behind LazyLock; fetch_one uses tested parse_host_port handling
bracketed IPv6. Gate green: 329 lib + 34 bin + 12 property + 3 doctests,
0 failed.
